#include "emailui.h"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMetaType>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QQuickView>
#include <QStandardPaths>
#include <QUrl>
#include <QUrlQuery>
#include <QUuid>
#include <QRegularExpression>

namespace {
const QString ServiceName = QStringLiteral("com.jolla.email.ui");
const QString ObjectPath = QStringLiteral("/com/jolla/email/ui");
const QString ShareObjectPath = QStringLiteral("/share");
}

EmailUi::EmailUi(QQuickView *view, QObject *parent)
    : QObject(parent)
    , m_view(view)
    , m_ready(false)
    , m_owned(false)
    , m_shareObject(new QObject(this))
{
    new EmailUiAdaptor(this);
    new EmailShareAdaptor(m_shareObject, this);
    // Content shared without a file of its own was put down for the composer
    // during an earlier run; it has been sent or dropped by now.
    QDir(QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
         + QStringLiteral("/share")).removeRecursively();
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
        bus.unregisterObject(ShareObjectPath);
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
    if (!bus.registerObject(ShareObjectPath, m_shareObject))
        qWarning("[sfmail][dbus] could not export %s", qPrintable(ShareObjectPath));
    if (!bus.registerService(ServiceName)) {
        // Someone else has it — in practice the stock client or the productive
        // harbour-sfmail is running. Nothing is broken, notifications just keep
        // going there; the About page reports the difference between "switched
        // on" and "actually holding it".
        qWarning("[sfmail][dbus] %s already owned — notifications stay with the "
                 "other client", qPrintable(ServiceName));
        bus.unregisterObject(ObjectPath);
        bus.unregisterObject(ShareObjectPath);
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

// D-Bus hands nested containers over as QDBusArgument; unwrap to plain Qt types
// — at every level, including the values of a map that arrived as a map.
static QVariant plainVariant(const QVariant &v)
{
    if (v.type() == QVariant::Map) {
        QVariantMap m = v.toMap();
        for (auto it = m.begin(); it != m.end(); ++it) it.value() = plainVariant(it.value());
        return m;
    }
    if (v.type() == QVariant::List) {
        QVariantList l = v.toList();
        for (int i = 0; i < l.size(); ++i) l[i] = plainVariant(l.at(i));
        return l;
    }
    if (v.userType() == qMetaTypeId<QDBusVariant>())
        return plainVariant(v.value<QDBusVariant>().variant());
    if (v.userType() == qMetaTypeId<QDBusArgument>()) {
        const QDBusArgument arg = v.value<QDBusArgument>();
        if (arg.currentType() == QDBusArgument::MapType) {
            QVariantMap m;
            arg >> m;
            for (auto it = m.begin(); it != m.end(); ++it) it.value() = plainVariant(it.value());
            return m;
        }
        if (arg.currentType() == QDBusArgument::ArrayType) {
            if (arg.currentSignature() == QLatin1String("as")) {    // plain list of paths
                QStringList sl;
                arg >> sl;
                QVariantList l;
                for (const QString &x : sl) l << x;
                return l;
            }
            QVariantList l;
            arg >> l;
            for (int i = 0; i < l.size(); ++i) l[i] = plainVariant(l.at(i));
            return l;
        }
    }
    return v;
}

// Anything on the session bus can call share(). The app's own data — keys,
// the plaintext caches, logs, the address list — must never leave as an
// attachment on a stranger's say-so, so files under the app's private folders
// and its staging folder are refused.
static bool isPrivatePath(const QString &path)
{
    const QString real = QFileInfo(path).canonicalFilePath();
    if (real.isEmpty()) return true;
    QString downloads = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (downloads.isEmpty()) downloads = QDir::homePath() + QStringLiteral("/Downloads");
    const QStringList roots = QStringList()
        << QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        << QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
        << QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        << downloads + QStringLiteral("/sfmail");
    for (const QString &r : roots) {
        const QString root = QFileInfo(r).canonicalFilePath();
        if (!root.isEmpty() && (real == root || real.startsWith(root + QLatin1Char('/'))))
            return true;
    }
    return false;
}

// A name or media type from the caller ends up in MIME headers: no control
// characters (a CR/LF would start a header of the caller's choosing).
static QString headerSafe(const QString &in)
{
    QString out;
    for (const QChar c : in)
        if (c.unicode() >= 0x20 && c.unicode() != 0x7f) out += c;
    return out.trimmed();
}

// What the system's share sheet hands over: "resources", each either a file
// (a path or file:// URL) or content without a file ({"name","data","type"}).
// Content is written to the app's cache so the composer can attach it like
// any file; a text-only share becomes the message body.
void EmailUi::share(const QVariantMap &configIn)
{
    const QVariantMap config = plainVariant(QVariant(configIn)).toMap();
    QVariantList files;
    QString body;
    // A folder of its own per share: a composer from an earlier share may still
    // point at its files by path, and one of the same name must never replace
    // them underneath it (the attachment would go to the wrong recipient).
    const QString cacheDir = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
                             + QStringLiteral("/share/")
                             + QUuid::createUuid().toString().mid(1, 36);
    static const int kMaxShareBytes = 64 * 1024 * 1024;
    const QVariantList resources = config.value(QStringLiteral("resources")).toList();
    for (const QVariant &r : resources) {
        if (r.type() == QVariant::String || r.type() == QVariant::Url) {
            QString path = r.toString();
            if (path.startsWith(QLatin1String("file://"))) path = QUrl(path).toLocalFile();
            if (!QFileInfo(path).isFile()) continue;
            if (isPrivatePath(path)) {
                qWarning("[sfmail][dbus] share: refused a file from the app's own data");
                continue;
            }
            QVariantMap f;
            f[QStringLiteral("path")] = path;
            f[QStringLiteral("name")] = headerSafe(QFileInfo(path).fileName());
            files << f;
            continue;
        }
        const QVariantMap m = r.toMap();
        const QByteArray data = m.value(QStringLiteral("data")).toByteArray();
        QString type = headerSafe(m.value(QStringLiteral("type")).toString());
        static const QRegularExpression mimeRe(QStringLiteral("^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$"));
        if (!mimeRe.match(type).hasMatch()) type.clear();
        if (data.size() > kMaxShareBytes) continue;          // not a mail attachment
        if (data.isEmpty()) {
            const QString status = m.value(QStringLiteral("status")).toString();
            if (!status.isEmpty()) body += (body.isEmpty() ? QString() : QStringLiteral("\n")) + status;
            continue;
        }
        if (type.startsWith(QLatin1String("text/")) && !m.contains(QStringLiteral("name"))) {
            body += (body.isEmpty() ? QString() : QStringLiteral("\n")) + QString::fromUtf8(data);
            continue;
        }
        QString name = headerSafe(QFileInfo(m.value(QStringLiteral("name")).toString()).fileName());
        if (name.isEmpty() || name == QLatin1String(".") || name == QLatin1String(".."))
            name = QStringLiteral("shared");
        QDir().mkpath(cacheDir);
        const QString path = cacheDir + QLatin1Char('/') + name;
        QFile out(path);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) continue;
        out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        if (out.write(data) != data.size()) { out.close(); QFile::remove(path); continue; }
        out.close();
        QVariantMap f;
        f[QStringLiteral("path")] = path;
        f[QStringLiteral("name")] = name;
        f[QStringLiteral("mimeType")] = type;
        files << f;
    }
    qDebug("[sfmail][dbus] share: %d file(s)", files.size());
    request(QStringLiteral("share"), QVariantList() << QVariant(files)
                                                    << config.value(QStringLiteral("linkTitle")).toString()
                                                    << body);
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
    } else if (kind == QLatin1String("share")) {
        emit shareRequested(args.value(0).toList(), args.value(1).toString(),
                            args.value(2).toString());
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

EmailShareAdaptor::EmailShareAdaptor(QObject *exported, EmailUi *ui)
    : QDBusAbstractAdaptor(exported)
    , m_ui(ui)
{
}

void EmailShareAdaptor::share(const QVariantMap &shareActionConfiguration)
{
    m_ui->share(shareActionConfiguration);
}
