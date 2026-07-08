#include <QtQuick>
#include <QGuiApplication>
#include <QQuickView>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>
#include <QTranslator>
#include <QLocale>
#include <QQmlContext>
#include <atomic>
#include <sailfishapp.h>
#include "logcontrol.h"

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
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
// default handler, and the kernel writes a core with the REAL original stack
// (core_pattern must point somewhere real). The marker's timestamp lets us line
// the crash up with the surrounding [send]/[diag] log lines.
static int g_crashFd = -1;

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
    writeAll(g_crashFd, " (core dumped; see gdb) ===\n");
    if (g_crashFd >= 0) fsync(g_crashFd);
    writeAll(STDERR_FILENO, hdr); writeAll(STDERR_FILENO, name); writeAll(STDERR_FILENO, "\n");

    // SA_RESETHAND already reset us to SIG_DFL; returning re-faults into the core.
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

// Runtime switch for the debug.log file (About → "Debug logging"). Default ON;
// the persisted choice is loaded at startup below. Only gates the on-device
// logfile — stderr/journal output stays on.
std::atomic<bool> g_fileLog{true};

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
        QFile f(path);
        if (f.open(QIODevice::Append | QIODevice::Text)) {
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
    }

    // Bilingual: load the German strings ONLY when the system language is German;
    // for every other language the app stays on its English source strings.
    if (QLocale::system().language() == QLocale::German) {
        QTranslator *de = new QTranslator(app.data());
        if (de->load(QStringLiteral("harbour-sfmail-de"),
                     SailfishApp::pathTo(QStringLiteral("translations")).toLocalFile()))
            app->installTranslator(de);
    }

    QScopedPointer<QQuickView> view(SailfishApp::createView());
    // Expose the debug-log switch to QML (About page).
    LogControl *logControl = new LogControl(view.data());
    view->rootContext()->setContextProperty(QStringLiteral("DebugLog"), logControl);
    view->setSource(SailfishApp::pathTo(QStringLiteral("qml/harbour-sfmail.qml")));
    view->showFullScreen();
    return app->exec();
}
