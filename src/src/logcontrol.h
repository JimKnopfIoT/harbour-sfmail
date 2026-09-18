#ifndef LOGCONTROL_H
#define LOGCONTROL_H

#include <QObject>
#include <QSettings>
#include <QStandardPaths>
#include <QStringList>
#include <atomic>

// Process-wide flag the message handler in main.cpp checks before writing a line
// to debug.log. Defined in main.cpp; toggled here and read in the hot logger path.
extern std::atomic<bool> g_fileLog;

// Defined in main.cpp: the recorded traces of a stalled mail delivery, and a
// way to drop them again. Kept apart from debug.log — see the comment there.
QStringList sfmailSyncIssueLines();
void sfmailClearSyncIssues();

// Exposed to QML as the context property "DebugLog" so the About page can offer a
// switch (by request): turn the debug.log file on/off at runtime. The choice
// is persisted in signed.ini (same store as the other app settings) and restored at
// startup. stderr/journal output is unaffected — only the on-device logfile.
class LogControl : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool enabled READ enabled WRITE setEnabled NOTIFY enabledChanged)
public:
    explicit LogControl(QObject *parent = nullptr) : QObject(parent) {}

    static QString storePath()
    {
        return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
               + QStringLiteral("/signed.ini");
    }
    // Default OFF. The log mirrors every Qt/QML message, which includes the
    // account address a message was sent from, attachment file names and the
    // certificate subjects gpgsm prints — a record of who the user corresponds
    // with, in the clear, growing for as long as nobody looks. It is a
    // diagnostic tool and is switched on when one is needed (About → Debug
    // logging).
    static bool readSetting()
    {
        QSettings s(storePath(), QSettings::IniFormat);
        return s.value(QStringLiteral("debugLogging"), false).toBool();
    }

    // About → "When mail stops arriving". The lines are collected whether or not
    // debug logging is on, because the fault they describe is not ours to fix
    // and the user needs to be able to show what happened.
    Q_INVOKABLE QStringList syncIssues() const { return sfmailSyncIssueLines(); }
    Q_INVOKABLE void clearSyncIssues() { sfmailClearSyncIssues(); }

    bool enabled() const { return g_fileLog.load(); }
    void setEnabled(bool on)
    {
        if (g_fileLog.load() == on) return;
        g_fileLog.store(on);
        QSettings s(storePath(), QSettings::IniFormat);
        s.setValue(QStringLiteral("debugLogging"), on);
        s.sync();
        emit enabledChanged();
    }

signals:
    void enabledChanged();
};

#endif // LOGCONTROL_H
