#include <QtQuick>
#include <QGuiApplication>
#include <QQuickView>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>
#include <QSocketNotifier>
#include <QTranslator>
#include <QLocale>
#include <QQmlContext>
#include <atomic>
#include <sailfishapp.h>
#include "logcontrol.h"
#include "emailui.h"

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <cstring>
#include <cstdint>

// Crash marker. The post-send "app closes/crashes" report leaves NO trace: it
// happens during QMF teardown after the last log line. On a fatal signal we
// write ONE async-signal-safe marker line to the logfile (via a pre-opened fd,
// no Qt/malloc), UNCONDITIONALLY (independent of the Debug-logging switch, since
// a crash is exactly when the switch might be off). We deliberately do NOT walk
// the stack here: glibc backtrace() re-faults inside the unwinder on a corrupt
// stack, which destroys the original context. Instead, with SA_RESETHAND we just
// RETURN — the faulting instruction re-executes, faults again against the now
// default handler, and the process dies with the REAL original signal. Since the
// PR_SET_DUMPABLE(0) hardening in main() there is no core anymore — the marker's
// timestamp lines the crash up with the surrounding [send]/[diag] log lines, and
// the journal shows the signal; for a core-level dig, temporarily comment the
// prctl out.
static int g_crashFd = -1;
// PIDs of the GnuPG daemons the crypto plugin spawned. A crash skips
// aboutToQuit, so a surviving agent would keep the launch sandbox alive and the
// app could not be started from its icon again (the reason those daemons are
// shut down at all). Read only inside the signal handler — hence plain atomics
// and kill(), both of which are safe there.
//
// The plugin reports them through the C function below, looked up at runtime.
// Sharing the variable itself would tie the plugin's load to a symbol of the
// executable, and a plugin that fails to load takes the whole UI with it.
static std::atomic<int> g_agentPids[4];

extern "C" void sfmail_note_agent_pid(int slot, int pid)
{
    if (slot >= 0 && slot < int(sizeof(g_agentPids) / sizeof(g_agentPids[0])))
        g_agentPids[slot].store(pid);
}

static void writeAll(int fd, const char *s)
{
    if (fd < 0 || !s) return;
    size_t len = strlen(s);
    while (len) {
        ssize_t n = write(fd, s, len);
        if (n <= 0) break;
        s += n; len -= static_cast<size_t>(n);
    }
}

// Async-signal-safe: kill() only, on pids the plugin reported.
static void killAgents()
{
    for (unsigned i = 0; i < sizeof(g_agentPids) / sizeof(g_agentPids[0]); ++i) {
        const int pid = g_agentPids[i].load();
        if (pid > 0) kill(pid, SIGTERM);
    }
}

static void crashHandler(int sig, siginfo_t *info, void *)
{
    const char *name = "signal";
    switch (sig) {
    case SIGSEGV: name = "SIGSEGV"; break;
    case SIGABRT: name = "SIGABRT"; break;
    case SIGBUS:  name = "SIGBUS";  break;
    case SIGFPE:  name = "SIGFPE";  break;
    case SIGILL:  name = "SIGILL";  break;
    }
    // Fault address in hex, formatted by hand (no snprintf in a signal handler).
    char addr[2 + 2 * sizeof(void *) + 1] = "0x";
    const uintptr_t a = reinterpret_cast<uintptr_t>(info ? info->si_addr : nullptr);
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 2 * sizeof(void *); ++i)
        addr[2 + i] = hex[(a >> ((2 * sizeof(void *) - 1 - i) * 4)) & 0xf];
    addr[2 + 2 * sizeof(void *)] = '\0';

    const char *hdr = "\n=== [CRASH] fatal ";
    writeAll(g_crashFd, hdr);     writeAll(g_crashFd, name);
    writeAll(g_crashFd, " at ");  writeAll(g_crashFd, addr);
    writeAll(g_crashFd, " ===\n");
    if (g_crashFd >= 0) fsync(g_crashFd);
    writeAll(STDERR_FILENO, hdr); writeAll(STDERR_FILENO, name); writeAll(STDERR_FILENO, "\n");

    killAgents();

    // SA_RESETHAND already reset us to SIG_DFL; returning re-faults into the core.
}

// Ending by signal (a kill from a script, the session going down) never reaches
// Qt's aboutToQuit either, and a GnuPG agent that outlives the process keeps the
// launch sandbox alive: the launcher then holds its single-instance lock and the
// app cannot be started from its icon again until someone kills the agent by
// hand.
//
// Killing recorded pids from the handler is not enough here — an agent started
// moments ago may not be recorded yet. So the signal is turned back into an
// ordinary quit: the handler writes one byte into a pipe (all it may do), the
// event loop picks it up and asks the application to quit, and the normal
// shutdown runs, which asks each agent to stop over its own protocol.
static int g_termPipe[2] = {-1, -1};

static void termHandler(int sig)
{
    const char b = char(sig);
    if (g_termPipe[1] >= 0) {
        ssize_t r = write(g_termPipe[1], &b, 1);
        (void)r;
    }
}

// Wire the pipe into the event loop. Runs in the main thread, so the handler
// itself only writes a byte and everything real happens here.
static void installTermHandler(QObject *owner)
{
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, g_termPipe) != 0) return;
    QSocketNotifier *n = new QSocketNotifier(g_termPipe[0], QSocketNotifier::Read, owner);
    QObject::connect(n, &QSocketNotifier::activated, owner, [n]() {
        n->setEnabled(false);
        char b; ssize_t r = ::read(g_termPipe[0], &b, 1); (void)r;
        qWarning() << "[sfmail] termination signal — shutting down";
        QCoreApplication::quit();
    });
    signal(SIGTERM, termHandler);
    signal(SIGINT,  termHandler);
    signal(SIGHUP,  termHandler);
}

static void installCrashHandler(const QString &logPath)
{
    g_crashFd = ::open(logPath.toLocal8Bit().constData(),
                       O_WRONLY | O_APPEND | O_CREAT, 0600);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crashHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND | SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);
    sigaction(SIGFPE,  &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);
}

// Runtime switch for the debug.log file (About → "Debug logging"). Default OFF
// (see logcontrol.h for why); the persisted choice is loaded at startup below.
// Only gates the on-device logfile — stderr/journal output stays on.
std::atomic<bool> g_fileLog{false};

// Development logging: mirror every Qt/QML message into a logfile under the
// app's data dir, so QML warnings ("Type X unavailable", ReferenceErrors, …)
// can be read without ssh/journalctl. Path:
//   ~/.local/share/harbour-sfmail-pgp/debug.log
static void fileMessageHandler(QtMsgType type, const QMessageLogContext &ctx,
                               const QString &msg)
{
    static QMutex mutex;
    static QString path;
    if (path.isEmpty()) {
        const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dir);
        path = dir + QStringLiteral("/debug.log");
    }

    const char *lvl = "D";
    switch (type) {
    case QtDebugMsg:    lvl = "D"; break;
    case QtInfoMsg:     lvl = "I"; break;
    case QtWarningMsg:  lvl = "W"; break;
    case QtCriticalMsg: lvl = "C"; break;
    case QtFatalMsg:    lvl = "F"; break;
    }

    QString line = QStringLiteral("%1 [%2] %3")
            .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
            .arg(QString::fromLatin1(lvl))
            .arg(msg);
    if (ctx.file && *ctx.file)
        line += QStringLiteral("  (%1:%2)").arg(QString::fromUtf8(ctx.file)).arg(ctx.line);

    // Write to the on-device logfile only when debug logging is enabled
    // (About → "Debug logging"). The stderr/journal line below is always emitted.
    if (g_fileLog.load()) {
        QMutexLocker lock(&mutex);
        // Bounded: this file records a session's activity and must not grow
        // without end on a phone. At the cap the previous log is kept as .1 and
        // a fresh one starts — two files, never more.
        static const qint64 kMaxBytes = 2 * 1024 * 1024;
        if (QFileInfo(path).size() > kMaxBytes) {
            QFile::remove(path + QStringLiteral(".1"));
            QFile::rename(path, path + QStringLiteral(".1"));
        }
        QFile f(path);
        const bool fresh = !QFileInfo::exists(path);
        if (f.open(QIODevice::Append | QIODevice::Text)) {
            if (fresh)
                f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
            QTextStream(&f) << line << '\n';
        }
    }
    // Keep the default stderr/journal output as well.
    QByteArray local = line.toLocal8Bit();
    fprintf(stderr, "%s\n", local.constData());
}

int main(int argc, char *argv[])
{
    qInstallMessageHandler(fileMessageHandler);

    // The process holds PGP/S-MIME passphrases and decrypted private key
    // material (gpgme, in-memory S/MIME repack). Non-dumpable means no ptrace
    // and no /proc/<pid>/mem for other processes of the same user; only root
    // can still look inside. The price is that a crash leaves no core dump —
    // debug.log (crash marker below) and the journal are the diagnostic tools
    // on the device anyway.
    prctl(PR_SET_DUMPABLE, 0);

    QScopedPointer<QGuiApplication> app(SailfishApp::application(argc, argv));

    // PIN the data location. QStandardPaths::AppDataLocation = ~/.local/share/
    // <organizationName>/<applicationName>; if we don't set these explicitly the
    // values depend on Sailjail's runtime injection and can DRIFT (e.g. to a
    // different app-name), so the keyring under sfmail/harbour-sfmail "disappears"
    // because the app then looks in the wrong directory. Pinning them to exactly
    // the X-Sailjail values (OrganizationName=sfmail) keeps the keyring path
    // deterministic AND inside the sandbox whitelist.
    QCoreApplication::setOrganizationName(QStringLiteral("sfmail"));
    QCoreApplication::setApplicationName(QStringLiteral("harbour-sfmail"));

    // Restore the persisted debug-logging choice now that the settings path is
    // deterministic (it depends on the org/app name set just above).
    g_fileLog.store(LogControl::readSetting());

    // Arm the crash catcher now that AppDataLocation is deterministic. Writes a
    // backtrace into debug.log on a fatal signal even if file logging is off.
    {
        const QString logDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(logDir);
        installCrashHandler(logDir + QStringLiteral("/debug.log"));
        installTermHandler(app.data());
    }

    // Load the translation for the device's language. QTranslator's locale-aware
    // load() does the narrowing itself (pt_BR → pt, de_AT → de) and simply finds
    // nothing for a language we do not ship — the app then shows its English
    // source strings, which is the intended fallback.
    {
        QTranslator *tr = new QTranslator(app.data());
        if (tr->load(QLocale::system(), QStringLiteral("harbour-sfmail"),
                     QStringLiteral("-"),
                     SailfishApp::pathTo(QStringLiteral("translations")).toLocalFile()))
            app->installTranslator(tr);
        else
            delete tr;
    }

    QScopedPointer<QQuickView> view(SailfishApp::createView());
    // Expose the debug-log switch to QML (About page).
    LogControl *logControl = new LogControl(view.data());
    view->rootContext()->setContextProperty(QStringLiteral("DebugLog"), logControl);

    // Serve com.jolla.email.ui, so a tap on a new-mail notification lands here
    // and not in the stock client. The context property has to exist before the
    // QML is loaded (the root window binds to it); the bus name is claimed right
    // after, because from that moment calls can arrive and QML must be there to
    // take them — anything still too early is queued inside EmailUi.
    EmailUi *emailUi = new EmailUi(view.data(), view.data());
    view->rootContext()->setContextProperty(QStringLiteral("EmailUi"), emailUi);
    view->setSource(SailfishApp::pathTo(QStringLiteral("qml/harbour-sfmail.qml")));
    emailUi->registerService();
    view->showFullScreen();
    return app->exec();
}
