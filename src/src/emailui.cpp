#include "emailui.h"

#include <QDBusConnection>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QQuickView>
#include <QStandardPaths>
#include <QUrl>
#include <QUrlQuery>

namespace {
const QString ServiceName = QStringLiteral("com.jolla.email.ui");
const QString ObjectPath = QStringLiteral("/com/jolla/email/ui");
}

EmailUi::EmailUi(QQuickView *view, QObject *parent)
    : QObject(parent)
    , m_view(view)
    , m_ready(false)
    , m_owned(false)
{
    new EmailUiAdaptor(this);
}

QString EmailUi::statePath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/notification-takeover");
}

bool EmailUi::takeoverEnabled() const
{
    QFile f(statePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return true;    // absent = ON: taking the notifications over is this app's
                        // long-standing default (0.5.1); the switch is the opt-out
    return f.readAll().trimmed() != QByteArray("0");
}

void EmailUi::setTakeoverEnabled(bool on)
{
    const QString path = statePath();
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        f.write(on ? "1\n" : "0\n");
        f.close();
    } else {
        qWarning("[sfmail][dbus] cannot write %s — the switch will not survive a "
                 "restart and the dispatcher keeps handing back", qPrintable(path));
    }

    // Act on it immediately, so the switch means something without a restart.
    if (on) {
        registerService();          // may fail: the other client still holds it
    } else if (m_owned) {
        QDBusConnection bus = QDBusConnection::sessionBus();
        bus.unregisterService(ServiceName);
        bus.unregisterObject(ObjectPath);
        m_owned = false;
        qDebug("[sfmail][dbus] released %s", qPrintable(ServiceName));
    }
    emit takeoverChanged();
}

bool EmailUi::registerService()
{
    if (!takeoverEnabled()) {
        // The user opted out (About → System): hand the notifications back to
        // whichever client owned them before this package was installed.
        qDebug("[sfmail][dbus] notification hand-off is off — not claiming %s",
               qPrintable(ServiceName));
        return false;
    }

    QDBusConnection bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) {
        qWarning("[sfmail][dbus] no session bus — notification hand-off disabled");
        return false;
    }
    // Object first, name second: between the two a caller could already be
    // dispatched to us, and an exported-but-nameless object is harmless whereas
    // the reverse loses the call.
    if (!bus.registerObject(ObjectPath, this)) {
        qWarning("[sfmail][dbus] could not export %s", qPrintable(ObjectPath));
        return false;
    }
    if (!bus.registerService(ServiceName)) {
        // Someone else has it — in practice the stock client or the productive
        // harbour-sfmail is running. Nothing is broken, notifications just keep
        // going there; the About page reports the difference between "switched
        // on" and "actually holding it".
        qWarning("[sfmail][dbus] %s already owned — notifications stay with the "
                 "other client", qPrintable(ServiceName));
        bus.unregisterObject(ObjectPath);
        m_owned = false;
        return false;
    }
    qDebug("[sfmail][dbus] owning %s", qPrintable(ServiceName));
    m_owned = true;
    return true;
}

void EmailUi::setReady()
{
    m_ready = true;
    const QVector<QPair<QString, QVariantList> > queued = m_pending;
    m_pending.clear();
    for (int i = 0; i < queued.size(); ++i)
        dispatch(queued.at(i).first, queued.at(i).second);
}

void EmailUi::openMessage(int messageId)
{
    request(QStringLiteral("openMessage"), QVariantList() << messageId);
}

void EmailUi::openCombinedInbox()
{
    request(QStringLiteral("openCombinedInbox"), QVariantList());
}

void EmailUi::openInbox(int accountId)
{
    request(QStringLiteral("openInbox"), QVariantList() << accountId);
}

// SF-Mail composes a reply from the opened message rather than from a bare id
// (the composer needs the original's account and crypto context, which
// MessagePage already works out). Opening the message is therefore the honest
// mapping — one tap short of the reply, and never a silently empty composer.
// Nothing in the notification path uses these; they exist so third-party callers
// of the stock interface don't hit an unknown method.
void EmailUi::replyToMessage(int messageId)
{
    request(QStringLiteral("openMessage"), QVariantList() << messageId);
}

void EmailUi::replyAllToMessage(int messageId)
{
    request(QStringLiteral("openMessage"), QVariantList() << messageId);
}

void EmailUi::compose(const QString &subject, const QString &to, const QString &cc,
                      const QString &bcc, const QString &body)
{
    request(QStringLiteral("compose"), QVariantList() << subject << to << cc << bcc << body);
}

void EmailUi::mailto(const QStringList &content)
{
    // Callers pass mailto: URLs (the browser and the share menu do), but a bare
    // address shows up too. Recipients accumulate across entries; the first entry
    // that carries subject/body/cc/bcc wins for those fields.
    QStringList recipients;
    QString subject, cc, bcc, body;

    for (int i = 0; i < content.size(); ++i) {
        const QString entry = content.at(i).trimmed();
        if (entry.isEmpty())
            continue;

        if (!entry.startsWith(QLatin1String("mailto:"), Qt::CaseInsensitive)) {
            recipients.append(entry);
            continue;
        }

        const QUrl url(entry);
        // In a mailto: URL the addresses sit in the path, comma separated.
        const QString path = url.path(QUrl::FullyDecoded);
        if (!path.isEmpty())
            recipients.append(path.split(QLatin1Char(','), QString::SkipEmptyParts));

        const QUrlQuery query(url);
        if (subject.isEmpty())
            subject = query.queryItemValue(QStringLiteral("subject"), QUrl::FullyDecoded);
        if (body.isEmpty())
            body = query.queryItemValue(QStringLiteral("body"), QUrl::FullyDecoded);
        if (cc.isEmpty())
            cc = query.queryItemValue(QStringLiteral("cc"), QUrl::FullyDecoded);
        if (bcc.isEmpty())
            bcc = query.queryItemValue(QStringLiteral("bcc"), QUrl::FullyDecoded);
    }

    compose(subject, recipients.join(QStringLiteral(", ")), cc, bcc, body);
}

void EmailUi::activateWindow(const QStringList &dummy)
{
    Q_UNUSED(dummy)
    // Pure "come to the front" — no page change, so it must not go through the
    // queue: replaying it later would yank the user out of whatever they opened
    // in the meantime.
    raiseWindow();
}

void EmailUi::request(const QString &kind, const QVariantList &args)
{
    raiseWindow();
    if (!m_ready) {
        m_pending.append(qMakePair(kind, args));
        return;
    }
    dispatch(kind, args);
}

void EmailUi::dispatch(const QString &kind, const QVariantList &args)
{
    if (kind == QLatin1String("openMessage")) {
        emit openMessageRequested(args.value(0).toInt());
    } else if (kind == QLatin1String("openInbox")) {
        emit openInboxRequested(args.value(0).toInt());
    } else if (kind == QLatin1String("openCombinedInbox")) {
        emit openCombinedInboxRequested();
    } else if (kind == QLatin1String("compose")) {
        emit composeRequested(args.value(0).toString(), args.value(1).toString(),
                              args.value(2).toString(), args.value(3).toString(),
                              args.value(4).toString());
    }
}

void EmailUi::raiseWindow()
{
    if (!m_view)
        return;
    m_view->raise();
    m_view->requestActivate();
}

EmailUiAdaptor::EmailUiAdaptor(EmailUi *parent)
    : QDBusAbstractAdaptor(parent)
{
}

EmailUi *EmailUiAdaptor::ui() const
{
    return static_cast<EmailUi *>(parent());
}

void EmailUiAdaptor::openMessage(int messageId) { ui()->openMessage(messageId); }
void EmailUiAdaptor::openCombinedInbox() { ui()->openCombinedInbox(); }
void EmailUiAdaptor::openInbox(int accountId) { ui()->openInbox(accountId); }
void EmailUiAdaptor::replyToMessage(int messageId) { ui()->replyToMessage(messageId); }
void EmailUiAdaptor::replyAllToMessage(int messageId) { ui()->replyAllToMessage(messageId); }

void EmailUiAdaptor::compose(const QString &emailSubject, const QString &emailTo,
                             const QString &emailCc, const QString &emailBcc,
                             const QString &emailBody)
{
    ui()->compose(emailSubject, emailTo, emailCc, emailBcc, emailBody);
}

void EmailUiAdaptor::mailto(const QStringList &content) { ui()->mailto(content); }
void EmailUiAdaptor::activateWindow(const QStringList &dummy) { ui()->activateWindow(dummy); }
