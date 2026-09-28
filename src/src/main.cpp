#include <QtQuick>
#include <QGuiApplication>
#include <QQuickView>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>
#include <QThreadStorage>
#include <QFileInfo>
#include <QSocketNotifier>
#include <QTranslator>
#include <QLocale>
#include <QQmlContext>
#include <QTimer>
#include <atomic>
#include <chrono>
#include <thread>
#include <ctime>
#include <cstdio>
#include <sailfishapp.h>
#include "logcontrol.h"
#include "mailservice.h"
#include "emailui.h"

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <cstring>
#include <dirent.h>
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
// The plugin publishes them as the application property "sfmailAgentPids";
// the watchdog's heartbeat copies them here. (A C function of this executable,
// looked up from the plugin, was never found: the launcher loads the program
// with RTLD_LOCAL.) The agents are the app's own children and die with it
// anyway — this covers an agent gpg started by itself.
static std::atomic<int> g_agentPids[4];

static void syncAgentPids()
{
    const QVariantList pids = qApp->property("sfmailAgentPids").toList();
    const int n = int(sizeof(g_agentPids) / sizeof(g_agentPids[0]));
    for (int i = 0; i < n; ++i)
        g_agentPids[i].store(i < pids.size() ? pids.at(i).toInt() : 0);
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

// When the request to end arrived (steady-clock ms, 0 = none). Should the main
// loop be blocked, the pipe is never read and the process would never end: the
// watchdog thread then ends it after a grace period, and a second signal ends
// it at once. Our agents are our children and go with it (PR_SET_PDEATHSIG).
static std::atomic<long long> g_termRequestedMs{0};
static long long steadyMs();

// The plaintext caches (decrypted attachments, the copies staged for "open
// with"). A forced end skips the app's own clean-up, so it empties them itself
// — with plain system calls, the main thread may be stuck holding a lock.
// Filled once at startup; the indexer markers (dot files) stay.
static char g_plainDirs[3][512];
// The S/MIME engine's working folders: while a message is signed or encrypted
// they hold its plaintext (gen-, import-, sign-, send-, verify- under this).
static char g_smimeHome[512];

static void removeFlatDir(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;
    while (struct dirent *e = readdir(d)) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        unlink(path);
    }
    closedir(d);
    rmdir(dir);
}

static void purgeSmimeWork()
{
    if (!g_smimeHome[0]) return;
    static const char *const prefixes[] = { "gen-", "import-", "sign-", "send-", "verify-" };
    DIR *d = opendir(g_smimeHome);
    if (!d) return;
    while (struct dirent *e = readdir(d)) {
        for (const char *pre : prefixes) {
            if (strncmp(e->d_name, pre, strlen(pre)) != 0) continue;
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", g_smimeHome, e->d_name);
            removeFlatDir(path);
            break;
        }
    }
    closedir(d);
}

static void purgePlainDirs()
{
    for (auto &dir : g_plainDirs) {
        if (!dir[0]) continue;
        DIR *d = opendir(dir);
        if (!d) continue;
        while (struct dirent *e = readdir(d)) {
            if (e->d_name[0] == '.') continue;
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            unlink(path);
        }
        closedir(d);
    }
    purgeSmimeWork();
}

static void notePlainDirs(const QStringList &dirs, const QString &smimeHome)
{
    for (int i = 0; i < 3 && i < dirs.size(); ++i) {
        const QByteArray p = QFile::encodeName(dirs.at(i));
        if (p.size() < int(sizeof(g_plainDirs[i])))
            memcpy(g_plainDirs[i], p.constData(), size_t(p.size()) + 1);
    }
    const QByteArray h = QFile::encodeName(smimeHome);
    if (h.size() < int(sizeof(g_smimeHome)))
        memcpy(g_smimeHome, h.constData(), size_t(h.size()) + 1);
}

static void termHandler(int sig)
{
    // Asked twice: end now — by way of the watchdog, which clears the plaintext
    // caches first (within a second).
    if (g_termRequestedMs.load() != 0) { g_termRequestedMs.store(1); (void)sig; return; }
    g_termRequestedMs.store(steadyMs());
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

// The debug-log switch (defined further down). The exit and stall markers are
// diagnostics like any other line and follow it; only the crash marker is
// written regardless, because a crash is exactly when nobody had it on.
extern std::atomic<bool> g_fileLog;

// Local time as "YYYY-MM-DDTHH:MM:SS", matching the log lines. Not for signal
// handlers (localtime_r may take a lock); fine at exit and in the watchdog.
static void stampNow(char *buf, size_t len)
{
    const time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tmv);
}

// The last line a process writes. If a session ends without "quitting" before
// it, the app never reached its normal shutdown; if this line is missing too,
// the process was killed from outside.
static void exitMarker()
{
    if (!g_fileLog.load()) return;
    char ts[32];
    stampNow(ts, sizeof(ts));
    writeAll(g_crashFd, ts);
    writeAll(g_crashFd, " === [EXIT] process exit ===\n");
}

// --- Main-loop watchdog ------------------------------------------------------
//
// A session that hangs never reaches aboutToQuit: the window is gone, the
// system eventually kills the process, and nothing in the log says why. A timer
// in the main thread leaves a heartbeat; a small thread of its own notices when
// the heartbeat stops and writes down for how long, and in which kernel
// function the main thread waits (/proc/.../wchan — a futex means a lock, a
// poll means it waits on a process or a socket). Steady clock: time the device
// spends suspended does not count as a stall.
static std::atomic<long long> g_heartbeatMs{0};

static long long steadyMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

static void watchdogLoop()
{
    const long long kStallMs = 6000;
    bool stalled = false;
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", int(getpid()));
    bool purgedOnTerm = false;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const long long termAt = g_termRequestedMs.load();
        // The system may follow its request to end with SIGKILL a second later,
        // and after that nothing runs any more: the plaintext goes right away.
        if (termAt != 0 && !purgedOnTerm) { purgePlainDirs(); purgedOnTerm = true; }
        if (termAt != 0 && steadyMs() - termAt > 3000) {
            // Asked to end, and the main loop has not got round to it.
            char ts[32];
            stampNow(ts, sizeof(ts));
            char line[160];
            snprintf(line, sizeof(line),
                     "%s === [EXIT] termination not handled within 3 s - ending now ===\n", ts);
            writeAll(g_crashFd, line);
            purgePlainDirs();
            killAgents();
            _exit(143);
        }
        const long long beat = g_heartbeatMs.load();
        if (beat == 0) continue;
        const long long age = steadyMs() - beat;
        char ts[32];
        stampNow(ts, sizeof(ts));
        if (!stalled && age > kStallMs) {
            stalled = true;
            char wchan[64] = "?";
            const int fd = ::open(path, O_RDONLY);
            if (fd >= 0) {
                const ssize_t n = ::read(fd, wchan, sizeof(wchan) - 1);
                wchan[n > 0 ? n : 0] = '\0';
                ::close(fd);
            }
            char line[192];
            snprintf(line, sizeof(line),
                     "%s === [STALL] main loop blocked for %lld s, waiting in %s ===\n",
                     ts, age / 1000, wchan);
            if (g_fileLog.load()) {
                writeAll(g_crashFd, line);
                writeAll(STDERR_FILENO, line);
            }
        } else if (stalled && age <= kStallMs) {
            stalled = false;
            char line[128];
            snprintf(line, sizeof(line), "%s === [STALL] main loop running again ===\n", ts);
            if (g_fileLog.load()) {
                writeAll(g_crashFd, line);
                writeAll(STDERR_FILENO, line);
            }
        }
    }
}

static void installWatchdog(QObject *owner)
{
    QTimer *beat = new QTimer(owner);
    beat->setTimerType(Qt::VeryCoarseTimer);
    beat->setInterval(2000);
    QObject::connect(beat, &QTimer::timeout, []() {
        g_heartbeatMs.store(steadyMs());
        syncAgentPids();
    });
    g_heartbeatMs.store(steadyMs());
    beat->start();
    std::thread(watchdogLoop).detach();
}

static void installCrashHandler(const QString &logPath)
{
    g_crashFd = ::open(logPath.toLocal8Bit().constData(),
                       O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
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
// Gates the on-device logfile and the copy in the system journal alike.
std::atomic<bool> g_fileLog{false};

// --- Stalled-delivery recorder ----------------------------------------------
//
// Mail retrieval on this platform is done by a system service that every mail
// application shares; this app only asks it for messages. That service keeps a
// process-wide count of reserved IMAP push connections and does not reliably
// give them back when a connection drops. Once the count passes its built-in
// ceiling it refuses to open ANY push connection — for every account at once —
// and accounts that fetch by push alone go silent until the service is
// restarted. No application can prevent this or clear that count.
//
// The service writes its own verdict to the system journal, which a sandboxed
// application may not read. What does reach us are the errors the mail library
// reports back into this process, so those are what we keep: they are the
// evidence that delivery stopped, and where.
//
// They live in a small file of their own rather than in debug.log, because that
// log is off by default (it records addresses and attachment names, these lines
// do not) and the evidence is needed exactly when nobody was logging. Mode
// 0600, a hard line cap, QMF status text and numeric account ids only.
static const int kSyncIssueMax = 40;

static QString syncIssuePath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/sync-issues.log");
}

static bool looksLikeStalledDelivery(const QString &msg)
{
    static const char *const marks[] = {
        "not progressing",        // the retrieval request timed out unanswered
        "push connections",       // the ceiling itself, if it ever reaches us
        "unable to reserve",
        "failed to download",
        "operation failed error code",
        "sync error account",
        "expired request",
        "internal state was reset",
    };
    for (const char *const m : marks)
        if (msg.contains(QLatin1String(m), Qt::CaseInsensitive))
            return true;
    return false;
}

// Appends one line and trims the file to the last kSyncIssueMax. Rewriting the
// whole file is fine: these lines arrive when delivery breaks, not in a loop.
static void recordSyncIssue(const QString &line)
{
    // Writing may itself produce a Qt warning, which would come straight back
    // through the message handler. The guard is per thread, but deliberately
    // not a thread_local: the executable must carry no thread-local storage of
    // its own. Its block would sit at the start of every thread's TLS area,
    // which the platform's graphics stack uses for itself on some devices; a
    // render thread reusing a finished thread's stack then inherits a stale
    // pointer there and crashes.
    static QThreadStorage<bool> busyFlag;
    bool &busy = busyFlag.localData();
    if (busy) return;
    busy = true;

    static QMutex mutex;
    QMutexLocker lock(&mutex);

    const QString path = syncIssuePath();
    QStringList kept;
    QFile in(path);
    if (in.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream s(&in);
        while (!s.atEnd()) {
            const QString l = s.readLine();
            if (!l.isEmpty()) kept << l;
        }
        in.close();
    }
    kept << line.left(400);
    while (kept.size() > kSyncIssueMax) kept.removeFirst();

    QFile out(path);
    const bool fresh = !QFileInfo::exists(path);
    if (out.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (fresh)
            out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        QTextStream s(&out);
        for (const QString &l : kept) s << l << '\n';
    }
    busy = false;
}

// Read back for the About page's report. Declared in logcontrol.h.
QStringList sfmailSyncIssueLines()
{
    QStringList out;
    QFile f(syncIssuePath());
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream s(&f);
        while (!s.atEnd()) {
            const QString l = s.readLine();
            if (!l.isEmpty()) out << l;
        }
    }
    return out;
}

void sfmailClearSyncIssues()
{
    QFile::remove(syncIssuePath());
}

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

    // Independent of the debug-log switch: the few lines that show mail
    // delivery has stopped are kept so the About page can show them afterwards.
    if ((type == QtWarningMsg || type == QtCriticalMsg) && looksLikeStalledDelivery(msg))
        recordSyncIssue(line);

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
    // The journal only while logging is on. These lines carry addresses,
    // subjects and attachment names, and the switch says "no log" — a copy in
    // the system journal would break that promise. Critical and fatal messages
    // still go there; the crash, stall and exit markers are written directly
    // and carry no mail data.
    if (g_fileLog.load() || type == QtCriticalMsg || type == QtFatalMsg) {
        QByteArray local = line.toLocal8Bit();
        fprintf(stderr, "%s\n", local.constData());
    }
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
        atexit(exitMarker);
        QString downloads = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
        if (downloads.isEmpty()) downloads = QDir::homePath() + QStringLiteral("/Downloads");
        notePlainDirs(QStringList()                  // as in the crypto plugin
                      << logDir + QStringLiteral("/decrypted")
                      << logDir + QStringLiteral("/smime-decrypted")
                      << downloads + QStringLiteral("/sfmail"),
                      logDir + QStringLiteral("/smime"));
        installWatchdog(app.data());
    }
    // Each step of the end of a session gets a line, so a log that stops early
    // says where: window gone → quitting (the agents are stopped here) → loop
    // left → [EXIT].
    QObject::connect(app.data(), &QGuiApplication::lastWindowClosed, []() {
        qWarning() << "[sfmail] window closed";
    });
    QObject::connect(app.data(), &QCoreApplication::aboutToQuit, []() {
        qWarning() << "[sfmail] quitting";
    });

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
    // Lets the delivery report restart the shared mail service (see
    // mailservice.h): the fault it works around lives in that process.
    MailService *mailService = new MailService(view.data());
    view->rootContext()->setContextProperty(QStringLiteral("MailService"), mailService);

    EmailUi *emailUi = new EmailUi(view.data(), view.data());
    view->rootContext()->setContextProperty(QStringLiteral("EmailUi"), emailUi);
    view->setSource(SailfishApp::pathTo(QStringLiteral("qml/harbour-sfmail.qml")));
    emailUi->registerService();
    view->showFullScreen();
    const int rc = app->exec();
    // From here the process only tears down. Should that hang (a destructor
    // waiting on a child, a lock), the watchdog ends it like an unanswered
    // termination request — otherwise it would sit there with the launch lock.
    if (g_termRequestedMs.load() == 0) g_termRequestedMs.store(steadyMs());
    // The agents were stopped on the way out; their pids may be reused by now.
    for (auto &pid : g_agentPids) pid.store(0);
    qWarning() << "[sfmail] event loop left, rc" << rc;
    return rc;
}
