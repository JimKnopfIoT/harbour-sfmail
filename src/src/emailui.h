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
public:
    explicit EmailUi(QQuickView *view, QObject *parent = nullptr);

    // Claims the bus name. Returns false if someone else already owns it (the
    // stock client is running); the app then just behaves as it did before —
    // losing the notification hand-off is not a reason to fail startup.
    bool registerService();

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
