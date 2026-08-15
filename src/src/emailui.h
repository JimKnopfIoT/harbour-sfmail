#ifndef EMAILUI_H
#define EMAILUI_H

#include <QObject>
#include <QPair>
#include <QStringList>
#include <QVariantList>
#include <QVector>
#include <QDBusAbstractAdaptor>

class QQuickView;

// Serves the com.jolla.email.ui D-Bus interface — the one the QMF notification
// plugin calls when a "new mail" banner is tapped. That plugin has service, path
// and method compiled in as plain UTF-16 literals (see libnotifications.so:
// com.jolla.email.ui, /com/jolla/email/ui, openMessage), so there is no setting
// that redirects a notification tap: whoever OWNS the name gets the tap. Claiming
// it here is what makes notifications open SF-Mail instead of the stock client.
//
// The same name also carries mailto: links and "share via email", hence the full
// interface rather than just openMessage — otherwise those would silently die.
class EmailUi : public QObject
{
    Q_OBJECT
    // About → System. "enabled" is what the user asked for and is persisted;
    // "owned" is what we actually got. They differ while the other client still
    // holds the name — the UI says so instead of pretending the switch failed.
    Q_PROPERTY(bool takeoverEnabled READ takeoverEnabled WRITE setTakeoverEnabled NOTIFY takeoverChanged)
    Q_PROPERTY(bool takeoverActive READ takeoverActive NOTIFY takeoverChanged)
public:
    explicit EmailUi(QQuickView *view, QObject *parent = nullptr);

    // Claims the bus name IF the user has switched the hand-off on. Returns
    // false if it is off, or if someone else already owns it (the other client
    // is running); the app then just behaves as it did before — losing the
    // notification hand-off is not a reason to fail startup.
    bool registerService();

    bool takeoverEnabled() const;
    void setTakeoverEnabled(bool on);
    bool takeoverActive() const { return m_owned; }

    // Where the marker lives that the app and the D-Bus dispatcher script share.
    // A plain file rather than a key in signed.ini: the dispatcher is /bin/sh and
    // has to read this on every activation, and "0" is harder to misparse than an
    // INI section. Absent = ON ("0" = off): taking the notifications over has
    // been this package's unconditional behaviour, so an update must not
    // silently change it — only an explicit "0" written by the switch does.
    static QString statePath();

    // A notification tap usually ACTIVATES us via D-Bus, so the method call beats
    // the QML engine to the finish line. Everything that arrives before QML says
    // it is ready is queued here and replayed, instead of being emitted into the
    // void.
    Q_INVOKABLE void setReady();

public slots:
    void openMessage(int messageId);
    void openCombinedInbox();
    void openInbox(int accountId);
    void replyToMessage(int messageId);
    void replyAllToMessage(int messageId);
    void compose(const QString &subject, const QString &to, const QString &cc,
                 const QString &bcc, const QString &body);
    void mailto(const QStringList &content);
    void activateWindow(const QStringList &dummy);

signals:
    void takeoverChanged();
    void openMessageRequested(int messageId);
    void openCombinedInboxRequested();
    void openInboxRequested(int accountId);
    void composeRequested(const QString &subject, const QString &to, const QString &cc,
                          const QString &bcc, const QString &body);

private:
    void request(const QString &kind, const QVariantList &args);
    void dispatch(const QString &kind, const QVariantList &args);
    void raiseWindow();

    QQuickView *m_view;
    bool m_ready;
    bool m_owned;               // do we currently hold com.jolla.email.ui?
    QVector<QPair<QString, QVariantList> > m_pending;
};

// Thin translation layer: it exists only so the exported interface NAME is
// com.jolla.email.ui (Qt would otherwise derive one from the class name) and so
// the exported signatures match the stock client's exactly — the notification
// plugin sends openMessage with an int32, and a mismatched signature is an
// unknown method as far as D-Bus is concerned.
class EmailUiAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "com.jolla.email.ui")
public:
    explicit EmailUiAdaptor(EmailUi *parent);

public slots:
    void openMessage(int messageId);
    void openCombinedInbox();
    void openInbox(int accountId);
    void replyToMessage(int messageId);
    void replyAllToMessage(int messageId);
    void compose(const QString &emailSubject, const QString &emailTo, const QString &emailCc,
                 const QString &emailBcc, const QString &emailBody);
    void mailto(const QStringList &content);
    Q_NOREPLY void activateWindow(const QStringList &dummy);

private:
    EmailUi *ui() const;
};

#endif // EMAILUI_H
