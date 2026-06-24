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
