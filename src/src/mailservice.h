#ifndef MAILSERVICE_H
#define MAILSERVICE_H

#include <QObject>
#include <QString>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDebug>

// Restarting the shared mail-retrieval service (About → "When mail stops
// arriving").
//
// That service keeps its count of reserved push-mail connections in its own
// process and does not reliably give them back, so once the count has run past
// its built-in ceiling it refuses to open any — for every account at once.
// The count exists nowhere but in that process: restarting it IS the remedy,
// and the only one an application can reach. Queued and received mail lives in
// the message store and is untouched; the session manager brings the unit
// straight back up.
//
// Talking to the session instance of the service manager is covered by the
// AppLaunch permission this app already declares (see the desktop entry);
// without it the call returns an access error, which is reported to the user
// rather than swallowed.
class MailService : public QObject
{
    Q_OBJECT
public:
    explicit MailService(QObject *parent = nullptr) : QObject(parent) {}

    // Empty unless the last restart() failed.
    Q_INVOKABLE QString lastError() const { return m_error; }

    Q_INVOKABLE bool restart()
    {
        m_error.clear();

        QDBusConnection bus = QDBusConnection::sessionBus();
        if (!bus.isConnected()) {
            m_error = tr("no connection to the session bus");
            return false;
        }

        // Built by hand rather than through QDBusInterface: that would
        // introspect the service manager first, which is a large reply we have
        // no use for.
        QDBusMessage call = QDBusMessage::createMethodCall(
                    QStringLiteral("org.freedesktop.systemd1"),
                    QStringLiteral("/org/freedesktop/systemd1"),
                    QStringLiteral("org.freedesktop.systemd1.Manager"),
                    QStringLiteral("RestartUnit"));
        call << QStringLiteral("messageserver5.service")
             << QStringLiteral("replace");

        const QDBusMessage reply = bus.call(call, QDBus::Block, 10000);
        if (reply.type() == QDBusMessage::ErrorMessage) {
            m_error = reply.errorMessage();
            if (m_error.isEmpty()) m_error = tr("refused, without a reason given");
            qWarning() << "[sync] restarting the mail service failed:" << m_error;
            return false;
        }
        qWarning() << "[sync] mail service restart requested";
        return true;
    }

private:
    QString m_error;
};

#endif // MAILSERVICE_H
