#include "GpgEngine.h"

#include <QProcess>
#include <QProcessEnvironment>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QRegExp>
#include <QVariantMap>
#include <QDateTime>
#include <QSettings>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDnsLookup>
#include <QHostAddress>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTimer>
#include <QDebug>

// App version, injected by the spec %build (single source of truth). Included
// UNCONDITIONALLY so qmake records the dependency and make rebuilds this TU when
// the version changes (a #if __has_include guard hides the include from qmake's
// scanner → stale version baked into the cached .o). The header is generated in
// %build before qmake runs; a checked-in copy keeps non-spec builds working.
#include "sfmail_version.h"
#ifndef SFMAIL_VERSION
#  define SFMAIL_VERSION "dev"
#endif

// QMF (libqmfclient) — used only for the PGP/MIME send path. The receive path
// stays on Nemo.Email/QML; this is the one place we talk to QMF directly,
// because Nemo.Email cannot build/send raw multipart/encrypted messages.
#include <qmailmessage.h>
#include <qmailaccount.h>
#include <qmailfolder.h>
#include <qmailstore.h>
#include <qmailserviceaction.h>
#include <qmailtimestamp.h>
#include <qmailaddress.h>

// Modern bundled GnuPG 2.2 stack, shipped under OUR OWN app prefix so the
// sandbox (which hides other apps' /usr/share/<app>) can see it.
static const char *kGpg = "/usr/share/harbour-sfmail/gpg/bin/gpg";
static const char *kLibDir = "/usr/share/harbour-sfmail/gpg/lib";
static const char *kAgent = "/usr/share/harbour-sfmail/gpg/bin/gpg-agent";

// Per-app keyring (modern format), separate from the unusable system ~/.gnupg.
static QString keyringHome()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/gnupg");
}

QString GpgEngine::gnupgHome() const { return keyringHome(); }

QString GpgEngine::appVersion() const { return QStringLiteral(SFMAIL_VERSION); }

GpgEngine::GpgEngine(QObject *parent) : QObject(parent)
{
    const QString home = keyringHome();
    QDir().mkpath(home);
    QFile::setPermissions(home, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);

    // Harden gpg-agent: never keep an unlocked secret key in agent memory beyond a
    // single operation. With cache TTL 0 + ignore-cache-for-signing the key is
    // decrypted only for the moment it is used, then dropped — shrinking the window
    // in which a live attacker (code execution on the unlocked device) could scrape
    // it from RAM. We always pass the passphrase via loopback anyway, so no UX cost.
    QFile ac(home + QStringLiteral("/gpg-agent.conf"));
    if (ac.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        ac.write("default-cache-ttl 0\n"
                 "max-cache-ttl 0\n"
                 "ignore-cache-for-signing\n"
                 "allow-loopback-pinentry\n");
        ac.close();
    }

    m_available = QFileInfo::exists(QString::fromUtf8(kGpg));

    // --- DIAGNOSTIC (0.3.80): a field report describes a local POP3 mail vanishing
    // right after saving an attachment. Listen for store-level message removals so the
    // next repro shows the exact moment (and count) a message leaves the DB. This
    // only reads IDs from a signal — it never constructs a QMailMessage(id), which
    // would freeze the GUI thread (see memory qmailmessage-im-plugin-friert-app-ein).
    if (QMailStore *st = QMailStore::instance()) {
        connect(st, &QMailStore::messagesRemoved, this,
                [](const QMailMessageIdList &ids) {
            QStringList s;
            for (const QMailMessageId &id : ids) s << QString::number(id.toULongLong());
            qWarning() << "[diag] messagesRemoved n=" << ids.size() << "ids=" << s.join(QStringLiteral(","));
        });
    }
}

// Run the bundled gpg against our keyring. stdinData is fed to stdin (used for
// the loopback passphrase, or plaintext when no passphrase is needed).
static bool runGpg(const QStringList &args, const QByteArray &stdinData,
                   QByteArray *out, QByteArray *err, int timeoutMs = 120000)
{
    QProcess p;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("LD_LIBRARY_PATH"), QString::fromUtf8(kLibDir));
    p.setProcessEnvironment(env);

    QStringList full;
    full << QStringLiteral("--homedir") << keyringHome()
         << QStringLiteral("--agent-program") << QString::fromUtf8(kAgent)
         << QStringLiteral("--batch") << QStringLiteral("--yes") << args;
    qWarning() << "[gpg] exec" << kGpg << "exists=" << QFileInfo::exists(QString::fromUtf8(kGpg))
               << "homedir=" << keyringHome() << "args=" << args.value(0);
    p.start(QString::fromUtf8(kGpg), full);
    if (!p.waitForStarted(5000)) {
        qWarning() << "[gpg] START FAILED:" << p.errorString();
        return false;
    }
    if (!stdinData.isEmpty())
        p.write(stdinData);
    p.closeWriteChannel();
    if (!p.waitForFinished(timeoutMs)) {
        qWarning() << "[gpg] TIMEOUT";
        p.kill();
        p.waitForFinished(2000);
        return false;
    }
    if (out) *out = p.readAllStandardOutput();
    QByteArray e = p.readAllStandardError();
    if (err) *err = e;
    const int ec = p.exitCode();
    qWarning() << "[gpg] exit=" << ec << "stderr=" << QString::fromUtf8(e).left(300);
    return p.exitStatus() == QProcess::NormalExit && ec == 0;
}

// Async variant of runGpg: starts the bundled gpg, feeds stdin once it is up,
// and invokes cb with (ok, stdout, stderr) when it finishes — WITHOUT blocking
// the GUI thread. Used for long-running operations like key generation. The
// QProcess cleans itself up (deleteLater) after cb returns.
static void runGpgAsync(const QStringList &args, const QByteArray &stdinData,
                        std::function<void(bool, QByteArray, QByteArray)> cb,
                        int timeoutMs = 300000)
{
    QProcess *p = new QProcess();
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("LD_LIBRARY_PATH"), QString::fromUtf8(kLibDir));
    p->setProcessEnvironment(env);

    QStringList full;
    full << QStringLiteral("--homedir") << keyringHome()
         << QStringLiteral("--agent-program") << QString::fromUtf8(kAgent)
         << QStringLiteral("--batch") << QStringLiteral("--yes") << args;

    // Feed stdin (loopback passphrase) only once the process is actually up.
    QObject::connect(p, &QProcess::started, p, [p, stdinData]() {
        if (!stdinData.isEmpty())
            p->write(stdinData);
        p->closeWriteChannel();
    });

    // Guard against a hung gpg.
    QTimer *killer = new QTimer(p);
    killer->setSingleShot(true);
    killer->setInterval(timeoutMs);
    QObject::connect(killer, &QTimer::timeout, p, [p]() {
        qWarning() << "[gpg-async] TIMEOUT, killing";
        p->kill();
    });

    QObject::connect(p,
                     static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
                     p, [p, cb](int code, QProcess::ExitStatus st) {
        const QByteArray out = p->readAllStandardOutput();
        const QByteArray err = p->readAllStandardError();
        const bool ok = (st == QProcess::NormalExit && code == 0);
        qWarning() << "[gpg-async] exit=" << code << "stderr=" << QString::fromUtf8(err).left(300);
        cb(ok, out, err);
        p->deleteLater();
    });
    QObject::connect(p, &QProcess::errorOccurred, p, [p, cb](QProcess::ProcessError e) {
        if (e != QProcess::FailedToStart) return;   // other errors still hit finished()
        qWarning() << "[gpg-async] START FAILED:" << p->errorString();
        cb(false, QByteArray(), p->errorString().toUtf8());
        p->deleteLater();
    });

    qWarning() << "[gpg-async] exec" << kGpg << "args=" << args.value(0);
    p->start(QString::fromUtf8(kGpg), full);
    killer->start();
}

// Pull the new key's fingerprint from gpg's status line
// "[GNUPG:] KEY_CREATED <type> <fingerprint>" (we route --status-fd to stderr).
static QString parseKeyCreated(const QByteArray &statusErr)
{
    const QString s = QString::fromUtf8(statusErr);
    const QStringList lines = s.split('\n');
    for (const QString &ln : lines) {
        const int i = ln.indexOf(QLatin1String("KEY_CREATED"));
        if (i < 0) continue;
        const QStringList parts = ln.mid(i).split(' ', QString::SkipEmptyParts);
        if (parts.size() >= 3) return parts.at(2).trimmed();   // KEY_CREATED <type> <fpr>
    }
    return QString();
}

// Write data to a short-lived temp file in the app's private area; returns path.
static QString writeTemp(const QByteArray &data, bool *ok)
{
    QString dir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    if (dir.isEmpty())
        dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    QString path = dir + QStringLiteral("/sfmail-gpg.tmp");
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) { *ok = false; return QString(); }
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    f.write(data);
    f.close();
    *ok = true;
    return path;
}

// Turn raw gpg stderr into a human-friendly message for common failures.
static QString friendlyGpgError(const QByteArray &errRaw)
{
    const QString err = QString::fromUtf8(errRaw);
    if (err.contains(QLatin1String("No secret key")))
        return QStringLiteral("This message is not encrypted to your key — you are not one of its recipients.");
    if (err.contains(QLatin1String("Bad passphrase")) || err.contains(QLatin1String("bad passphrase")))
        return QStringLiteral("Wrong passphrase.");
    if (err.contains(QLatin1String("No data")) || err.contains(QLatin1String("no valid OpenPGP data")))
        return QStringLiteral("No PGP data found in this part.");
    return err.trimmed();
}

static void parseUid(const QString &uid, QString *name, QString *email)
{
    int lt = uid.indexOf('<');
    int gt = uid.indexOf('>', lt + 1);
    if (lt >= 0 && gt > lt) {
        *email = uid.mid(lt + 1, gt - lt - 1);
        *name = uid.left(lt).trimmed();
    } else {
        *name = uid;
        *email = QString();
    }
}

static QString pgpAlgoName(const QString &n);            // defined further below
static QString epochToDate(const QString &s)
{
    bool ok = false;
    const uint t = s.toUInt(&ok);
    if (!ok || t == 0) return QString();
    return QDateTime::fromTime_t(t).date().toString(Qt::ISODate);
}

QVariantList GpgEngine::listKeys(bool secret, const QString &pattern)
{
    QVariantList result;
    QStringList args;
    args << (secret ? QStringLiteral("--list-secret-keys") : QStringLiteral("--list-keys"))
         << QStringLiteral("--with-colons");
    if (!pattern.isEmpty())
        args << pattern;

    QByteArray out;
    if (!runGpg(args, QByteArray(), &out, nullptr, 15000))
        return result;

    QSet<QString> secretFprs;
    if (!secret) {
        QByteArray sout;
        if (runGpg(QStringList() << QStringLiteral("--list-secret-keys")
                                 << QStringLiteral("--with-colons"),
                   QByteArray(), &sout, nullptr, 15000)) {
            for (const QByteArray &l : sout.split('\n')) {
                const QList<QByteArray> f = l.split(':');
                if (f.size() > 9 && f[0] == "fpr")
                    secretFprs.insert(QString::fromUtf8(f[9]));
            }
        }
    }

    QVariantMap cur;
    bool haveCur = false, haveUid = false;
    auto flush = [&]() {
        if (haveCur) {
            cur["hasSecret"] = secret ? true
                                      : secretFprs.contains(cur.value("fingerprint").toString());
            result.append(cur);
        }
        cur.clear(); haveCur = false; haveUid = false;
    };

    for (const QByteArray &lineRaw : out.split('\n')) {
        const QStringList f = QString::fromUtf8(lineRaw).split(':');
        if (f.isEmpty()) continue;
        const QString type = f[0];
        if (type == "pub" || type == "sec") {
            flush();
            haveCur = true;
            cur["keyId"] = f.value(4);
            cur["expired"] = (f.value(1) == "e");
            cur["revoked"] = (f.value(1) == "r");
            cur["bits"] = f.value(2);
            cur["algo"] = pgpAlgoName(f.value(3));
            cur["created"] = epochToDate(f.value(5));
            cur["expires"] = f.value(6).isEmpty() ? QStringLiteral("never") : epochToDate(f.value(6));
        } else if (type == "fpr" && haveCur) {
            if (!cur.contains("fingerprint")) cur["fingerprint"] = f.value(9);
        } else if (type == "uid" && haveCur && !haveUid) {
            QString name, email;
            parseUid(f.value(9), &name, &email);
            cur["uid"] = f.value(9); cur["name"] = name; cur["email"] = email;
            haveUid = true;
        }
    }
    flush();
    return result;
}

QVariantList GpgEngine::publicKeys(const QString &pattern) { return listKeys(false, pattern); }
QVariantList GpgEngine::secretKeys(const QString &pattern) { return listKeys(true, pattern); }

QString GpgEngine::exportPublicKey(const QString &fingerprint)
{
    QByteArray out;
    if (runGpg(QStringList() << QStringLiteral("--armor") << QStringLiteral("--export") << fingerprint,
               QByteArray(), &out, nullptr, 15000))
        return QString::fromUtf8(out);
    return QString();
}

QString GpgEngine::exportSecretKey(const QString &fingerprint, const QString &passphrase)
{
    QByteArray out, err;
    QStringList args;
    args << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
         << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
         << QStringLiteral("--armor") << QStringLiteral("--export-secret-keys") << fingerprint;
    if (runGpg(args, passphrase.toUtf8() + "\n", &out, &err, 30000) && !out.isEmpty())
        return QString::fromUtf8(out);
    qWarning() << "[gpg] export-secret-keys failed:" << QString::fromUtf8(err).left(200);
    return QString();
}

QString GpgEngine::saveKeyToDocuments(const QString &fingerprint, bool secret,
                                      const QString &passphrase)
{
    const QString armored = secret ? exportSecretKey(fingerprint, passphrase)
                                    : exportPublicKey(fingerprint);
    if (armored.isEmpty()) return QString();
    QString dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + QStringLiteral("/Documents");
    QDir().mkpath(dir);
    const QString shortId = fingerprint.right(16);
    const QString name = QStringLiteral("sfmail-") + shortId
                       + (secret ? QStringLiteral("-secret") : QString()) + QStringLiteral(".asc");
    const QString path = dir + QStringLiteral("/") + name;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return QString();
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    f.write(armored.toUtf8());
    f.close();
    return path;
}

// Best-effort secure delete of a file the user picked for import (its real path,
// wherever the picker found it — Downloads, Documents, /sdcard, …). Overwrites the
// content once before unlinking; on flash storage true shredding isn't guaranteed
// (wear levelling), but it removes the plaintext path. Returns true if removed.
bool GpgEngine::shredFile(const QString &path)
{
    QString p = path;
    if (p.startsWith(QStringLiteral("file://"))) p = p.mid(7);
    QFile f(p);
    if (!f.exists()) return false;
    if (f.open(QIODevice::ReadWrite)) {
        const qint64 sz = f.size();
        QByteArray zeros(static_cast<int>(qMin<qint64>(sz, 1 << 16)), '\0');
        qint64 written = 0;
        f.seek(0);
        while (written < sz) {
            const qint64 n = f.write(zeros.constData(), qMin<qint64>(zeros.size(), sz - written));
            if (n <= 0) break;
            written += n;
        }
        f.flush();
        f.close();
    }
    return QFile::remove(p);
}

void GpgEngine::liftSizeLimit()
{
    m_sizeLimitUntil = QDateTime::currentDateTime().addSecs(15 * 60);
    emit sizeLimitChanged();
}

bool GpgEngine::sizeLimitLifted()
{
    return m_sizeLimitUntil.isValid() && QDateTime::currentDateTime() < m_sizeLimitUntil;
}

QString GpgEngine::saveAttachmentToDocuments(const QString &cachePathOrUrl,
                                             const QString &suggestedName)
{
    return saveAttachmentTo(cachePathOrUrl, suggestedName, QString());
}

QString GpgEngine::saveAttachmentTo(const QString &cachePathOrUrl,
                                    const QString &suggestedName, const QString &destFolder)
{
    QString src = cachePathOrUrl;
    if (src.startsWith(QStringLiteral("file://"))) src = src.mid(7);
    if (!QFileInfo::exists(src)) return QString();
    QString dir = destFolder;
    if (dir.startsWith(QStringLiteral("file://"))) dir = dir.mid(7);
    if (dir.isEmpty()) dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + QStringLiteral("/Documents");
    QDir().mkpath(dir);
    QString base = suggestedName.trimmed();
    if (base.isEmpty()) base = QFileInfo(src).fileName();
    base = base.section('/', -1).section('\\', -1);   // basename only — no traversal
    if (base.isEmpty()) base = QStringLiteral("attachment");
    QString target = dir + QStringLiteral("/") + base;
    if (QFileInfo::exists(target)) {                  // de-duplicate
        QString stem = base, ext;
        const int dot = base.lastIndexOf('.');
        if (dot > 0) { stem = base.left(dot); ext = base.mid(dot); }
        for (int i = 1; i < 1000; ++i) {
            target = dir + QStringLiteral("/") + stem + QStringLiteral("-%1").arg(i) + ext;
            if (!QFileInfo::exists(target)) break;
        }
    }
    if (!QFile::copy(src, target)) return QString();
    return target;
}

bool GpgEngine::contentAvailable(int messageId)
{
    QMailMessageId mid(static_cast<quint64>(messageId));
    if (!mid.isValid()) return false;
    // Metadata-only load (lightweight, same as the list models use). Does NOT pull
    // the body or re-render — unlike a full QMailMessage(id), which freezes the GUI.
    QMailMessageMetaData meta(mid);
    return meta.contentAvailable();
}

void GpgEngine::extendKey(const QString &fingerprint, const QString &expiry,
                          const QString &passphrase)
{
    const QString exp = expiry.trimmed().isEmpty() ? QStringLiteral("2y") : expiry.trimmed();
    const QByteArray pass = passphrase.toUtf8() + "\n";
    QByteArray out, err;
    // Primary key first.
    bool ok = runGpg(QStringList() << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                                   << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                                   << QStringLiteral("--quick-set-expire") << fingerprint << exp,
                     pass, &out, &err, 30000);
    if (ok) {
        // Then all subkeys ("*").
        QByteArray o2, e2;
        runGpg(QStringList() << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                             << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                             << QStringLiteral("--quick-set-expire") << fingerprint << exp
                             << QStringLiteral("*"),
               pass, &o2, &e2, 30000);
    }
    if (ok) { emit keyOpFinished(true, QStringLiteral("Validity extended.")); emit keysChanged(); }
    else     emit keyOpFinished(false, friendlyGpgError(err));
}

// Path of gpg's auto-generated revocation certificate for this key.
static QString revocCertPath(const QString &fingerprint)
{
    return keyringHome() + QStringLiteral("/openpgp-revocs.d/")
           + fingerprint.toUpper() + QStringLiteral(".rev");
}

bool GpgEngine::hasRevocationCert(const QString &fingerprint)
{
    return QFileInfo::exists(revocCertPath(fingerprint));
}

QString GpgEngine::saveRevocationCert(const QString &fingerprint)
{
    const QString rev = revocCertPath(fingerprint);
    if (!QFileInfo::exists(rev)) return QString();
    QFile in(rev);
    if (!in.open(QIODevice::ReadOnly)) return QString();
    const QByteArray data = in.readAll();   // keep gpg's protective leading colon
    in.close();
    QString dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + QStringLiteral("/Documents");
    QDir().mkpath(dir);
    const QString path = dir + QStringLiteral("/sfmail-") + fingerprint.right(16)
                       + QStringLiteral("-revocation.asc");
    QFile out(path);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return QString();
    out.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    out.write(data);
    out.close();
    return path;
}

void GpgEngine::revokeKey(const QString &fingerprint)
{
    const QString rev = revocCertPath(fingerprint);
    if (!QFileInfo::exists(rev)) {
        emit keyOpFinished(false, QStringLiteral("No revocation certificate on file for this key "
                                                 "(only keys generated in the app have one)."));
        return;
    }
    QFile in(rev);
    if (!in.open(QIODevice::ReadOnly)) { emit keyOpFinished(false, QStringLiteral("Cannot read revocation cert.")); return; }
    QByteArray data = in.readAll();
    in.close();
    // Remove gpg's protective leading colon (":-----BEGIN…") so it actually applies.
    data.replace(QByteArray(":-----BEGIN"), QByteArray("-----BEGIN"));
    bool wrote = false;
    const QString tmp = writeTemp(data, &wrote);
    if (!wrote) { emit keyOpFinished(false, QStringLiteral("temp write failed")); return; }
    QByteArray io, ie;
    const bool ok = runGpg(QStringList() << QStringLiteral("--import") << tmp, QByteArray(), &io, &ie, 30000);
    QFile::remove(tmp);
    if (ok) {
        emit keyOpFinished(true, QStringLiteral("Key revoked. Publish it now so others stop using it."));
        emit keysChanged();
    } else {
        emit keyOpFinished(false, friendlyGpgError(ie));
    }
}

void GpgEngine::publishKey(const QString &fingerprint)
{
    const QString armored = exportPublicKey(fingerprint);
    if (armored.isEmpty()) { emit keyOpFinished(false, QStringLiteral("Could not export the public key.")); return; }
    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    QNetworkRequest req(QUrl(QStringLiteral("https://keys.openpgp.org/vks/v1/upload")));
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    QJsonObject obj;
    obj.insert(QStringLiteral("keytext"), armored);
    const QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QNetworkReply *rep = m_nam->post(req, body);
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray resp = rep->readAll();
        const QNetworkReply::NetworkError nerr = rep->error();
        rep->deleteLater();
        if (nerr == QNetworkReply::NoError && code == 200) {
            emit keyOpFinished(true, QStringLiteral("Uploaded to keys.openpgp.org. To make your "
                "e-mail address searchable there, open the verification mail they send you."));
            emit keysChanged();
        } else {
            emit keyOpFinished(false, QStringLiteral("Upload failed (HTTP %1): %2")
                               .arg(code).arg(QString::fromUtf8(resp).left(200)));
        }
    });
}

static QString capsToText(const QString &caps)
{
    QStringList c;
    if (caps.contains('s', Qt::CaseInsensitive)) c << QStringLiteral("sign");
    if (caps.contains('e', Qt::CaseInsensitive)) c << QStringLiteral("encrypt");
    if (caps.contains('c', Qt::CaseInsensitive)) c << QStringLiteral("certify");
    if (caps.contains('a', Qt::CaseInsensitive)) c << QStringLiteral("authenticate");
    return c.join(QStringLiteral(", "));
}

QVariantMap GpgEngine::keyDetails(const QString &fingerprint)
{
    QVariantMap m;
    QByteArray out;
    runGpg(QStringList() << QStringLiteral("--list-keys") << QStringLiteral("--with-colons")
                         << fingerprint, QByteArray(), &out, nullptr, 15000);

    QStringList uids;
    QVariantList subkeys;
    QString section;   // "pub" | "sub"
    for (const QByteArray &lineRaw : out.split('\n')) {
        const QStringList f = QString::fromUtf8(lineRaw).split(':');
        if (f.isEmpty()) continue;
        const QString t = f[0];
        if (t == QLatin1String("pub")) {
            section = QStringLiteral("pub");
            m[QStringLiteral("keyId")] = f.value(4);
            m[QStringLiteral("bits")] = f.value(2);
            m[QStringLiteral("algo")] = pgpAlgoName(f.value(3));
            m[QStringLiteral("created")] = epochToDate(f.value(5));
            m[QStringLiteral("expires")] = f.value(6).isEmpty() ? QStringLiteral("never") : epochToDate(f.value(6));
            const QString v = f.value(1);
            m[QStringLiteral("revoked")] = v.contains('r');
            m[QStringLiteral("expired")] = v.contains('e');
            m[QStringLiteral("caps")] = capsToText(f.value(11));
        } else if (t == QLatin1String("sub")) {
            section = QStringLiteral("sub");
            QVariantMap s;
            s[QStringLiteral("keyId")] = f.value(4);
            s[QStringLiteral("bits")] = f.value(2);
            s[QStringLiteral("algo")] = pgpAlgoName(f.value(3));
            s[QStringLiteral("created")] = epochToDate(f.value(5));
            s[QStringLiteral("expires")] = f.value(6).isEmpty() ? QStringLiteral("never") : epochToDate(f.value(6));
            s[QStringLiteral("caps")] = capsToText(f.value(11));
            const QString v = f.value(1);
            s[QStringLiteral("revoked")] = v.contains('r');
            s[QStringLiteral("expired")] = v.contains('e');
            subkeys.append(s);
        } else if (t == QLatin1String("fpr")) {
            if (section == QLatin1String("pub")) {
                if (!m.contains(QStringLiteral("fingerprint"))) m[QStringLiteral("fingerprint")] = f.value(9);
            } else if (section == QLatin1String("sub") && !subkeys.isEmpty()) {
                QVariantMap s = subkeys.last().toMap();
                s[QStringLiteral("fpr")] = f.value(9);
                subkeys.last() = s;
            }
        } else if (t == QLatin1String("uid")) {
            const QString u = f.value(9).trimmed();
            if (!u.isEmpty() && !uids.contains(u)) uids << u;
        }
    }
    m[QStringLiteral("uids")] = uids;
    m[QStringLiteral("subkeys")] = subkeys;
    m[QStringLiteral("status")] = m.value(QStringLiteral("revoked")).toBool() ? QStringLiteral("REVOKED")
                                  : m.value(QStringLiteral("expired")).toBool() ? QStringLiteral("expired")
                                  : QStringLiteral("valid");

    QByteArray sout;
    bool okSec = runGpg(QStringList() << QStringLiteral("--list-secret-keys") << QStringLiteral("--with-colons")
                                      << fingerprint, QByteArray(), &sout, nullptr, 15000);
    m[QStringLiteral("hasSecret")] = okSec && sout.contains("sec:");
    m[QStringLiteral("armored")] = exportPublicKey(fingerprint);
    return m;
}

void GpgEngine::importKeyFile(const QString &path)
{
    QFile ffile(path);
    if (!ffile.open(QIODevice::ReadOnly)) {
        emit importFinished(false, 0, QStringLiteral("Cannot open key file"));
        return;
    }
    importKeyText(QString::fromUtf8(ffile.readAll()));
}

void GpgEngine::importKeyText(const QString &armored)
{
    bool tok = false;
    const QString tmp = writeTemp(armored.toUtf8(), &tok);
    if (!tok) { emit importFinished(false, 0, QStringLiteral("temp write failed")); return; }
    QByteArray err;
    bool ok = runGpg(QStringList() << QStringLiteral("--import") << tmp, QByteArray(), nullptr, &err, 30000);
    QFile::remove(tmp);
    int imported = 0;
    for (const QByteArray &l : err.split('\n'))
        if (l.contains("imported")) imported++;
    if (ok) { emit importFinished(true, imported, QString()); emit keysChanged(); }
    else     emit importFinished(false, 0, QString::fromUtf8(err).trimmed());
}

void GpgEngine::fetchKey(const QString &query)
{
    const QString q = query.trimmed();
    if (q.isEmpty()) { emit keyFetchFinished(false, QStringLiteral("Nothing to look up.")); return; }

    QStringList urls;
    if (q.contains(QLatin1Char('@'))) {
        const QString e = QString::fromUtf8(QUrl::toPercentEncoding(q));
        urls << QStringLiteral("https://keys.openpgp.org/vks/v1/by-email/") + e
             << QStringLiteral("https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=") + e;
    } else {
        QString hex = q;
        hex.remove(QStringLiteral("0x"), Qt::CaseInsensitive);
        hex.remove(QLatin1Char(' '));
        hex = hex.toUpper();
        urls << (hex.length() >= 40
                     ? QStringLiteral("https://keys.openpgp.org/vks/v1/by-fingerprint/") + hex
                     : QStringLiteral("https://keys.openpgp.org/vks/v1/by-keyid/") + hex)
             << QStringLiteral("https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x") + hex;
    }
    emit keyFetchStarted();
    fetchKeyTry(urls, 0, q);
}

// Try each keyserver URL in turn; import the first key found.
void GpgEngine::fetchKeyTry(const QStringList &urls, int idx, const QString &query)
{
    if (idx >= urls.size()) {
        emit keyFetchFinished(false,
            QStringLiteral("No key found for \"%1\" on keys.openpgp.org or keyserver.ubuntu.com.").arg(query));
        return;
    }
    qWarning() << "[ks] try" << idx << urls[idx];
    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    QNetworkRequest req((QUrl(urls[idx])));
    req.setRawHeader("User-Agent", "harbour-sfmail");
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    QNetworkReply *reply = m_nam->get(req);
    const QStringList u = urls; const QString qq = query; const int i = idx;
    connect(reply, &QNetworkReply::finished, this, [this, reply, u, i, qq]() {
        const QByteArray data = reply->readAll();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        qWarning() << "[ks] reply" << i << "err=" << reply->error() << "http=" << code << "bytes=" << data.size();
        reply->deleteLater();
        if (reply->error() == QNetworkReply::NoError && data.contains("BEGIN PGP PUBLIC KEY BLOCK")) {
            const QString src = i == 0 ? QStringLiteral("keys.openpgp.org")
                                       : QStringLiteral("keyserver.ubuntu.com");
            importKeyText(QString::fromUtf8(data));   // emits importFinished + keysChanged
            emit keyFetchFinished(true,
                QStringLiteral("Key for \"%1\" found on %2 and imported.").arg(qq, src));
        } else {
            fetchKeyTry(u, i + 1, qq);   // next keyserver
        }
    });
}

// keys.openpgp.org ONLY — it serves a key by-email only when that address is
// VERIFIED on the key, so the email lookup is authoritative (essential for the
// "a different key is published for this address" warning to be trustworthy).
static QStringList keyserverUrls(const QString &query)
{
    QStringList urls;
    const QString q = query.trimmed();
    if (q.contains(QLatin1Char('@'))) {
        urls << QStringLiteral("https://keys.openpgp.org/vks/v1/by-email/")
                + QString::fromUtf8(QUrl::toPercentEncoding(q));
    } else {
        QString hex = q;
        hex.remove(QStringLiteral("0x"), Qt::CaseInsensitive);
        hex.remove(QLatin1Char(' '));
        hex = hex.toUpper();
        urls << (hex.length() >= 40
                     ? QStringLiteral("https://keys.openpgp.org/vks/v1/by-fingerprint/") + hex
                     : QStringLiteral("https://keys.openpgp.org/vks/v1/by-keyid/") + hex);
    }
    return urls;
}

void GpgEngine::httpGetFirst(const QStringList &urls, int idx, std::function<void(QByteArray)> cb)
{
    if (idx >= urls.size()) { cb(QByteArray()); return; }
    qWarning() << "[ks] get" << idx << urls[idx];
    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    QNetworkRequest req((QUrl(urls[idx])));
    req.setRawHeader("User-Agent", "harbour-sfmail");
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    QNetworkReply *reply = m_nam->get(req);
    const QStringList u = urls; const int i = idx;
    connect(reply, &QNetworkReply::finished, this, [this, reply, u, i, cb]() {
        const QByteArray data = reply->readAll();
        reply->deleteLater();
        if (reply->error() == QNetworkReply::NoError && data.contains("BEGIN PGP PUBLIC KEY BLOCK"))
            cb(data);
        else
            httpGetFirst(u, i + 1, cb);
    });
}

// Inspect an armored key WITHOUT importing it. Returns ALL contained key-ids —
// the primary AND every subkey (a message is encrypted to the ENCRYPTION SUBKEY,
// whose id differs from the primary, so we must match against subkeys too).
// keyIds[0] is the primary.
static void showKeyInfo(const QByteArray &armored, QStringList *keyIds, QString *uids, QString *primaryFpr)
{
    keyIds->clear(); *uids = QString(); *primaryFpr = QString();
    bool tok = false;
    const QString tmp = writeTemp(armored, &tok);
    if (!tok) return;
    QByteArray out;
    runGpg(QStringList() << QStringLiteral("--with-colons") << QStringLiteral("--import-options")
                         << QStringLiteral("show-only") << QStringLiteral("--import") << tmp,
           QByteArray(), &out, nullptr, 15000);
    QFile::remove(tmp);
    QStringList us;
    bool wantPrimaryFpr = false;
    for (const QByteArray &lr : out.split('\n')) {
        const QStringList f = QString::fromUtf8(lr).split(':');
        if (f.isEmpty()) continue;
        if (f[0] == QLatin1String("pub")) {
            const QString k = f.value(4); if (!k.isEmpty()) keyIds->append(k.toUpper());
            wantPrimaryFpr = primaryFpr->isEmpty();   // next fpr line = primary fpr
        } else if (f[0] == QLatin1String("sub")) {
            const QString k = f.value(4); if (!k.isEmpty()) keyIds->append(k.toUpper());
        } else if (f[0] == QLatin1String("fpr")) {
            if (wantPrimaryFpr) { *primaryFpr = f.value(9).toUpper(); wantPrimaryFpr = false; }
        } else if (f[0] == QLatin1String("uid")) {
            us << f.value(9);
        }
    }
    *uids = us.join(QStringLiteral("; "));
}

void GpgEngine::resolveMissingKey(const QString &wantedKeyId, const QString &email)
{
    emit keyFetchStarted();
    QString wanted = wantedKeyId;
    wanted.remove(QStringLiteral("0x"), Qt::CaseInsensitive);
    wanted = wanted.remove(QLatin1Char(' ')).toUpper();
    const QString em = email.trimmed();
    if (wanted.isEmpty() && em.isEmpty()) { emit keyFetchFinished(false, QStringLiteral("Nothing to look up.")); return; }

    // SECURITY: we NEVER auto-import. Whatever we find, we stash it and report
    // it (key-id, fingerprint, UIDs, and whether it actually contains the key
    // this message used) so the user can verify and decide.
    auto present = [this, wanted](const QByteArray &data) {
        QStringList ids; QString uids, fpr;
        showKeyInfo(data, &ids, &uids, &fpr);
        const QString primary = ids.isEmpty() ? QString() : ids.first();
        bool matches = false;
        for (const QString &id : ids)
            if (id.compare(wanted, Qt::CaseInsensitive) == 0) { matches = true; break; }
        m_pendingKeyArmored = data;
        m_pendingKeyId = primary;
        emit keyCandidate(primary, uids, matches, fpr);
    };

    auto tryEmail = [this, wanted, em, present]() {
        if (em.isEmpty() || !em.contains(QLatin1Char('@'))) {
            emit keyFetchFinished(false,
                QStringLiteral("Key 0x%1 is not published on keys.openpgp.org.").arg(wanted));
            return;
        }
        httpGetFirst(keyserverUrls(em), 0, [this, wanted, em, present](QByteArray edata) {
            if (edata.isEmpty())
                emit keyFetchFinished(false,
                    QStringLiteral("Neither key 0x%1 nor address %2 is published on keys.openpgp.org.").arg(wanted, em));
            else
                present(edata);
        });
    };

    if (wanted.isEmpty()) { tryEmail(); return; }
    httpGetFirst(keyserverUrls(wanted), 0, [this, present, tryEmail](QByteArray data) {
        if (!data.isEmpty()) present(data);
        else tryEmail();
    });
}

void GpgEngine::importPendingKey()
{
    if (m_pendingKeyArmored.isEmpty()) { emit keyFetchFinished(false, QStringLiteral("Nothing to import.")); return; }
    const QByteArray a = m_pendingKeyArmored;
    m_pendingKeyArmored.clear();
    importKeyText(QString::fromUtf8(a));   // emits importFinished + keysChanged
    emit keyFetchFinished(true, QStringLiteral("The other key was imported."));
}

// Inspect a public key WITHOUT importing (show-only). Returns a map with keyId,
// fpr (primary), uids, emails[], created/expires/algo/bits and revoked/expired.
// Empty map if no public key could be read.
static QVariantMap inspectArmoredKey(const QByteArray &armored)
{
    QVariantMap m;
    bool tok = false;
    const QString tmp = writeTemp(armored, &tok);
    if (!tok) return m;
    QByteArray out;
    runGpg(QStringList() << QStringLiteral("--with-colons") << QStringLiteral("--import-options")
                         << QStringLiteral("show-only") << QStringLiteral("--import") << tmp,
           QByteArray(), &out, nullptr, 15000);
    QFile::remove(tmp);

    QStringList uids, emails;
    bool havePub = false, wantPrimaryFpr = false;
    for (const QByteArray &lr : out.split('\n')) {
        const QStringList f = QString::fromUtf8(lr).split(':');
        if (f.isEmpty()) continue;
        if (f[0] == QLatin1String("pub")) {
            if (havePub) continue;            // only the FIRST key block matters here
            havePub = true;
            const QString v = f.value(1);
            m[QStringLiteral("keyId")] = f.value(4);
            m[QStringLiteral("bits")] = f.value(2);
            m[QStringLiteral("algo")] = pgpAlgoName(f.value(3));
            m[QStringLiteral("created")] = epochToDate(f.value(5));
            const QString exp = f.value(6);
            m[QStringLiteral("expires")] = exp.isEmpty() ? QStringLiteral("never") : epochToDate(exp);
            bool revoked = v.contains('r');
            bool expired = v.contains('e');
            if (!exp.isEmpty()) {             // validity field is often '-' in show-only → also check the date
                bool okNum = false; qint64 e = exp.toLongLong(&okNum);
                if (okNum && e > 0 && e < QDateTime::currentMSecsSinceEpoch() / 1000) expired = true;
            }
            m[QStringLiteral("revoked")] = revoked;
            m[QStringLiteral("expired")] = expired;
            wantPrimaryFpr = true;
        } else if (f[0] == QLatin1String("fpr")) {
            if (wantPrimaryFpr) { m[QStringLiteral("fpr")] = f.value(9).toUpper(); wantPrimaryFpr = false; }
        } else if (f[0] == QLatin1String("uid")) {
            const QString u = f.value(9);
            if (u.isEmpty() || uids.contains(u)) continue;
            uids << u;
            QString name, email; parseUid(u, &name, &email);
            email = email.toLower();
            if (!email.isEmpty() && !emails.contains(email)) emails << email;
        }
    }
    if (!havePub) return QVariantMap();
    m[QStringLiteral("uids")] = uids.join(QStringLiteral("; "));
    m[QStringLiteral("emails")] = emails;
    return m;
}

void GpgEngine::inspectKeyForImport(const QString &armored, const QString &senderEmail)
{
    const QByteArray raw = armored.toUtf8();
    QVariantMap info = inspectArmoredKey(raw);
    if (info.isEmpty() || info.value(QStringLiteral("fpr")).toString().isEmpty()) {
        emit importFinished(false, 0, QStringLiteral("No readable PGP public key in this message."));
        return;
    }
    const QString fpr = info.value(QStringLiteral("fpr")).toString().toUpper();

    // Does this key actually belong to the mail's SENDER? A PGP key attachment can
    // carry ANY identity, so we cross-check the key's UID addresses against the
    // From address. senderEmail may be "Name <addr>" → extract the bare address.
    QString sender = senderEmail.trimmed().toLower();
    const int lt = sender.indexOf(QLatin1Char('<'));
    if (lt >= 0) {
        const int gt = sender.indexOf(QLatin1Char('>'), lt + 1);
        if (gt > lt) sender = sender.mid(lt + 1, gt - lt - 1).trimmed();
    }
    info[QStringLiteral("senderEmail")] = sender;
    info[QStringLiteral("senderKnown")] = !sender.isEmpty();
    info[QStringLiteral("senderMatches")] =
        !sender.isEmpty() && info.value(QStringLiteral("emails")).toStringList().contains(sender);

    // Do we already have THIS exact key?
    bool inKeyring = false;
    for (const QVariant &v : publicKeys(fpr)) {
        if (v.toMap().value(QStringLiteral("fingerprint")).toString().toUpper() == fpr) { inKeyring = true; break; }
    }
    info[QStringLiteral("inKeyring")] = inKeyring;

    // Is a DIFFERENT key already stored for one of this key's addresses? That is the
    // risky case (a stale/forged key being re-added) → the UI must ask, not import.
    QVariantList conflicts;
    QSet<QString> seen;
    const QStringList emails = info.value(QStringLiteral("emails")).toStringList();
    for (const QString &em : emails) {
        for (const QVariant &v : publicKeys(em)) {
            const QVariantMap k = v.toMap();
            const QString kf = k.value(QStringLiteral("fingerprint")).toString().toUpper();
            if (kf.isEmpty() || kf == fpr || seen.contains(kf)) continue;
            seen.insert(kf);
            QVariantMap c;
            c[QStringLiteral("fpr")] = kf;
            c[QStringLiteral("keyId")] = k.value(QStringLiteral("keyId"));
            c[QStringLiteral("uid")] = k.value(QStringLiteral("uid"));
            c[QStringLiteral("email")] = em;
            c[QStringLiteral("revoked")] = k.value(QStringLiteral("revoked"));
            c[QStringLiteral("expired")] = k.value(QStringLiteral("expired"));
            conflicts.append(c);
        }
    }
    info[QStringLiteral("conflicts")] = conflicts;
    info[QStringLiteral("valid")] = !info.value(QStringLiteral("revoked")).toBool()
                                 && !info.value(QStringLiteral("expired")).toBool();

    m_pendingKeyArmored = raw;
    m_pendingKeyId = info.value(QStringLiteral("keyId")).toString();
    emit keyImportCandidate(info);
}

void GpgEngine::inspectKeyFileForImport(const QString &path, const QString &senderEmail)
{
    QString p = path;
    if (p.startsWith(QStringLiteral("file://"))) p = p.mid(7);
    QFile f(p);
    if (!f.open(QIODevice::ReadOnly)) {
        emit importFinished(false, 0, QStringLiteral("Cannot open key file"));
        return;
    }
    inspectKeyForImport(QString::fromUtf8(f.readAll()), senderEmail);
}

void GpgEngine::deleteKey(const QString &fingerprint, bool deleteSecret)
{
    QByteArray err;
    bool ok = true;
    if (deleteSecret)
        ok = runGpg(QStringList() << QStringLiteral("--delete-secret-keys") << fingerprint,
                    QByteArray(), nullptr, &err, 60000);
    if (ok)
        ok = runGpg(QStringList() << QStringLiteral("--delete-keys") << fingerprint,
                    QByteArray(), nullptr, &err, 30000);
    if (ok) { emit keyDeleted(true, QString()); emit keysChanged(); }
    else     emit keyDeleted(false, QString::fromUtf8(err).trimmed());
}

// Create a fresh RSA-4096 OpenPGP key pair in the app keyring: primary cert,sign
// first, then an RSA-4096 encryption subkey. Asynchronous (gpg can take a while);
// each step uses loopback passphrase via stdin. New key lands in our own keyring
// → immediately usable, NO trust step needed (web-of-trust via fingerprint).
void GpgEngine::generateKey(const QString &name, const QString &email,
                            const QString &passphrase, const QString &expiry)
{
    if (!m_available) {
        emit keyGenFinished(false, QString(), QStringLiteral("gpg is not available"));
        return;
    }
    const QString trimmedName = name.trimmed();
    const QString trimmedMail = email.trimmed();
    const QString uid = trimmedName.isEmpty()
            ? trimmedMail
            : trimmedName + QStringLiteral(" <") + trimmedMail + QStringLiteral(">");
    const QString exp = expiry.trimmed().isEmpty() ? QStringLiteral("2y") : expiry.trimmed();
    const QByteArray pass = passphrase.toUtf8() + "\n";

    emit keyGenStarted();

    // Step 1 — RSA-4096 primary key, usage cert,sign. --status-fd 2 makes gpg
    // print KEY_CREATED (with the new fingerprint) onto stderr.
    QStringList genArgs;
    genArgs << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
            << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
            << QStringLiteral("--status-fd") << QStringLiteral("2")
            << QStringLiteral("--quick-generate-key") << uid
            << QStringLiteral("rsa4096") << QStringLiteral("cert,sign") << exp;

    runGpgAsync(genArgs, pass, [this, pass, exp](bool ok, QByteArray, QByteArray err) {
        if (!ok) {
            emit keyGenFinished(false, QString(), friendlyGpgError(err));
            return;
        }
        const QString fpr = parseKeyCreated(err);
        if (fpr.isEmpty()) {
            // Primary was created but we couldn't read its fingerprint back; the
            // key exists and is usable for signing — just refresh the list.
            emit keyGenFinished(true, QString(), QString());
            emit keysChanged();
            return;
        }
        // Step 2 — add an RSA-4096 encryption subkey to the just-made primary.
        QStringList subArgs;
        subArgs << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                << QStringLiteral("--quick-add-key") << fpr
                << QStringLiteral("rsa4096") << QStringLiteral("encrypt") << exp;
        runGpgAsync(subArgs, pass, [this, fpr](bool ok2, QByteArray, QByteArray err2) {
            if (!ok2) {
                // Primary is fine but the encryption subkey failed — report it so
                // the user can retry adding one rather than think nothing happened.
                emit keyGenFinished(false, fpr,
                    QStringLiteral("Primary key created, but adding the encryption subkey failed: ")
                    + friendlyGpgError(err2));
                emit keysChanged();
                return;
            }
            emit keyGenFinished(true, fpr, QString());
            emit keysChanged();
        });
    });
}

// Synchronous encrypt (+ optional sign) of raw bytes. armored result in *out.
bool GpgEngine::encryptRaw(const QStringList &recipientFingerprints, const QByteArray &plaintext,
                           const QString &signFingerprint, const QString &passphrase,
                           QByteArray *out, QByteArray *err)
{
    QStringList args;
    args << QStringLiteral("--armor") << QStringLiteral("--trust-model") << QStringLiteral("always");
    for (const QString &fpr : recipientFingerprints)
        args << QStringLiteral("--recipient") << fpr;

    QByteArray stdinData;
    QString plainTmp;
    if (!signFingerprint.isEmpty()) {
        // Signing needs the passphrase via stdin, so the plaintext goes to a
        // short-lived temp file in our private area.
        args << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
             << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
             << QStringLiteral("--local-user") << signFingerprint << QStringLiteral("--sign");
        bool tok = false;
        plainTmp = writeTemp(plaintext, &tok);
        if (!tok) { if (err) *err = "temp write failed"; return false; }
        args << QStringLiteral("--encrypt") << QStringLiteral("--output") << QStringLiteral("-") << plainTmp;
        stdinData = passphrase.toUtf8() + "\n";
    } else {
        // No signing → no passphrase; feed plaintext via stdin.
        args << QStringLiteral("--encrypt") << QStringLiteral("--output") << QStringLiteral("-");
        stdinData = plaintext;
    }

    bool ok = runGpg(args, stdinData, out, err);
    if (!plainTmp.isEmpty()) QFile::remove(plainTmp);
    return ok;
}

void GpgEngine::encrypt(const QStringList &recipientFingerprints, const QString &plaintext,
                        const QString &signFingerprint, const QString &passphrase)
{
    QByteArray out, err;
    bool ok = encryptRaw(recipientFingerprints, plaintext.toUtf8(), signFingerprint, passphrase, &out, &err);
    if (ok) emit encryptFinished(true, QString::fromUtf8(out), QString());
    else    emit encryptFinished(false, QString(), QString::fromUtf8(err).trimmed());
}

// Synchronous DETACHED armored signature over raw bytes. The data goes to a
// temp file (the passphrase occupies stdin via loopback). SHA-256 so the
// multipart/signed micalg is deterministic ("pgp-sha256").
bool GpgEngine::signRaw(const QByteArray &data, const QString &signFingerprint,
                        const QString &passphrase, QByteArray *out, QByteArray *err)
{
    QStringList args;
    args << QStringLiteral("--armor") << QStringLiteral("--detach-sign")
         << QStringLiteral("--digest-algo") << QStringLiteral("SHA256")
         << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
         << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
         << QStringLiteral("--local-user") << signFingerprint;
    bool tok = false;
    const QString tmp = writeTemp(data, &tok);
    if (!tok) { if (err) *err = "temp write failed"; return false; }
    args << QStringLiteral("--output") << QStringLiteral("-") << tmp;
    bool ok = runGpg(args, passphrase.toUtf8() + "\n", out, err);
    QFile::remove(tmp);
    return ok && out && !out->isEmpty();
}

// Inline clear-text signature (gpg --clearsign), NO encryption. Result via
// encryptFinished() so the QML inline-send flow is reused unchanged.
void GpgEngine::clearSign(const QString &text, const QString &signFingerprint,
                          const QString &passphrase)
{
    QStringList args;
    args << QStringLiteral("--armor") << QStringLiteral("--clearsign")
         << QStringLiteral("--digest-algo") << QStringLiteral("SHA256")
         << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
         << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
         << QStringLiteral("--local-user") << signFingerprint
         << QStringLiteral("--output") << QStringLiteral("-");
    bool tok = false;
    const QString tmp = writeTemp(text.toUtf8(), &tok);
    if (!tok) { emit encryptFinished(false, QString(), QStringLiteral("temp write failed")); return; }
    args << tmp;
    QByteArray out, err;
    bool ok = runGpg(args, passphrase.toUtf8() + "\n", &out, &err);
    QFile::remove(tmp);
    if (ok && !out.isEmpty()) emit encryptFinished(true, QString::fromUtf8(out), QString());
    else                      emit encryptFinished(false, QString(), friendlyGpgError(err));
}

// --- MIME parsing for the decrypted PGP/MIME payload -----------------------

static QByteArray decodeQuotedPrintable(const QByteArray &in)
{
    QByteArray out;
    for (int i = 0; i < in.size(); ++i) {
        char c = in.at(i);
        if (c == '=' && i + 2 < in.size()) {
            if (in.at(i + 1) == '\r' && in.at(i + 2) == '\n') { i += 2; continue; }  // soft break
            if (in.at(i + 1) == '\n') { i += 1; continue; }
            bool ok = false;
            int v = in.mid(i + 1, 2).toInt(&ok, 16);
            if (ok) { out.append(char(v)); i += 2; continue; }
        }
        out.append(c);
    }
    return out;
}

// Unfold RFC 822 headers: join continuation lines (those starting with WS) onto
// the previous line, so each logical header is one string.
static QString unfoldHeaders(const QByteArray &header)
{
    QString h = QString::fromUtf8(header);
    h.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    const QStringList raw = h.split('\n');
    QStringList logical;
    for (const QString &line : raw) {
        if ((line.startsWith(' ') || line.startsWith('\t')) && !logical.isEmpty())
            logical.last() += QStringLiteral(" ") + line.trimmed();
        else
            logical.append(line);
    }
    return logical.join('\n');
}

// Return the raw value of a header (everything after "Name:" up to newline),
// case-insensitive on the name. "" if absent.
static QString headerValue(const QString &unfolded, const QString &name)
{
    for (const QString &line : unfolded.split('\n')) {
        int c = line.indexOf(':');
        if (c < 0) continue;
        if (line.left(c).trimmed().compare(name, Qt::CaseInsensitive) == 0)
            return line.mid(c + 1).trimmed();
    }
    return QString();
}

// Extract a parameter (e.g. boundary, filename, name, charset) from a header
// value, handling quoted and unquoted forms. "" if absent.
static QString headerParam(const QString &unfolded, const QString &name, const QString &param)
{
    const QString val = headerValue(unfolded, name);
    if (val.isEmpty()) return QString();
    const QString needle = param.toLower() + QStringLiteral("=");
    const QString low = val.toLower();
    int p = low.indexOf(needle);
    if (p < 0) return QString();
    QString rest = val.mid(p + needle.length()).trimmed();
    if (rest.startsWith('"')) {
        int e = rest.indexOf('"', 1);
        return e > 0 ? rest.mid(1, e - 1) : rest.mid(1);
    }
    int e = rest.length();
    for (int k = 0; k < rest.length(); ++k)
        if (rest[k] == ';' || rest[k].isSpace()) { e = k; break; }
    return rest.left(e);
}

struct MimeAttachment {
    QString name;
    QString mimeType;
    QByteArray data;
    bool inlineImage = false;
};

// Size limits (anti memory-bomb DoS). A crafted message can't make us allocate
// unboundedly: oversized parts are skipped before decoding, and we stop once the
// running total / part count is reached. Tunable knobs — raise if you routinely
// receive bigger attachments.
static const qint64 kMaxPartBytes  = 64LL * 1024 * 1024;   // per part (encoded)
static const qint64 kMaxTotalBytes = 128LL * 1024 * 1024;  // all parts together
static const int    kMaxParts      = 256;                   // number of leaves
static const int    kMaxTextBytes  = 8 * 1024 * 1024;       // readable text body

struct MimeBudget { qint64 total = 0; int parts = 0; bool truncated = false; bool unlimited = false; };

// Recursively walk a MIME tree, collecting readable text and every leaf that is
// not inline body text (attachments, images). Best-effort, defensive on depth
// AND size (budget) so a malicious or huge message cannot exhaust memory.
static void walkMime(const QByteArray &mime, QString *textOut,
                     QList<MimeAttachment> *atts, int depth, MimeBudget *budget)
{
    if (depth > 12) return;
    if (!budget->unlimited && (budget->parts >= kMaxParts || budget->total >= kMaxTotalBytes)) {
        budget->truncated = true;
        return;
    }
    int sep = mime.indexOf("\r\n\r\n"); int seplen = 4;
    if (sep < 0) { sep = mime.indexOf("\n\n"); seplen = 2; }
    const QByteArray header = sep >= 0 ? mime.left(sep) : mime;
    const QByteArray body   = sep >= 0 ? mime.mid(sep + seplen) : QByteArray();

    const QString h = unfoldHeaders(header);
    const QString ctypeFull = headerValue(h, QStringLiteral("content-type"));
    const QString ctype = ctypeFull.section(';', 0, 0).trimmed().toLower();
    const QString cte = headerValue(h, QStringLiteral("content-transfer-encoding")).toLower();
    const QString cdisp = headerValue(h, QStringLiteral("content-disposition")).toLower();

    if (ctype.startsWith(QStringLiteral("multipart/"))) {
        QString bnd = headerParam(h, QStringLiteral("content-type"), QStringLiteral("boundary"));
        if (bnd.isEmpty()) return;
        const QByteArray delim = "--" + bnd.toUtf8();
        // Split the body into parts on lines that begin with the boundary.
        QList<QByteArray> chunks;
        QByteArray cur;
        bool started = false;
        for (const QByteArray &lineRaw : body.split('\n')) {
            QByteArray line = lineRaw;
            if (line.endsWith('\r')) line.chop(1);
            if (line.startsWith(delim)) {
                if (started && !cur.isEmpty()) chunks.append(cur);
                cur.clear();
                started = true;
                if (line == delim + "--") break;  // closing delimiter
                continue;
            }
            if (started) { cur.append(lineRaw); cur.append('\n'); }
        }
        const QString subtype = ctype.mid(QStringLiteral("multipart/").length());
        if (subtype == QStringLiteral("alternative")) {
            // Prefer the text/plain alternative; fall back to the first part.
            int chosen = -1;
            for (int i = 0; i < chunks.size(); ++i) {
                const QString ch = QString::fromUtf8(chunks[i].left(400)).toLower();
                if (ch.contains(QStringLiteral("text/plain"))) { chosen = i; break; }
            }
            if (chosen < 0 && !chunks.isEmpty()) chosen = 0;
            if (chosen >= 0) walkMime(chunks[chosen], textOut, atts, depth + 1, budget);
        } else {
            for (const QByteArray &ch : chunks) {
                if (!budget->unlimited && (budget->parts >= kMaxParts || budget->total >= kMaxTotalBytes)) {
                    budget->truncated = true;
                    break;
                }
                walkMime(ch, textOut, atts, depth + 1, budget);
            }
        }
        return;
    }

    // Leaf part. Guard on the ENCODED size BEFORE decoding, so an oversized part
    // never gets allocated/decoded at all (base64 decodes to ≤ the encoded size).
    if (!budget->unlimited && body.size() > kMaxPartBytes) { budget->truncated = true; return; }

    QByteArray decoded = body;
    if (cte.contains(QStringLiteral("quoted-printable"))) decoded = decodeQuotedPrintable(body);
    else if (cte.contains(QStringLiteral("base64")))      decoded = QByteArray::fromBase64(body);

    budget->parts += 1;
    budget->total += decoded.size();

    QString filename = headerParam(h, QStringLiteral("content-disposition"), QStringLiteral("filename"));
    if (filename.isEmpty())
        filename = headerParam(h, QStringLiteral("content-type"), QStringLiteral("name"));
    const bool isAttachment = cdisp.contains(QStringLiteral("attachment")) || !filename.isEmpty();

    if (!isAttachment && ctype == QStringLiteral("text/plain")) {
        if (budget->unlimited || textOut->size() < kMaxTextBytes) {
            if (!textOut->isEmpty()) textOut->append(QStringLiteral("\n"));
            textOut->append(QString::fromUtf8(decoded));
        } else budget->truncated = true;
    } else if (!isAttachment && ctype.isEmpty()) {
        // No content-type on a leaf: treat as plain text.
        if (budget->unlimited || textOut->size() < kMaxTextBytes) {
            if (!textOut->isEmpty()) textOut->append(QStringLiteral("\n"));
            textOut->append(QString::fromUtf8(decoded));
        } else budget->truncated = true;
    } else if (!isAttachment && ctype == QStringLiteral("text/html")) {
        // Keep HTML only if there was no plain alternative at all.
        if (textOut->isEmpty()) {
            QString s = QString::fromUtf8(decoded);
            s.remove(QRegExp(QStringLiteral("<[^>]*>")));
            textOut->append(s.trimmed());
        }
    } else {
        // Attachment / inline image / any non-text leaf.
        MimeAttachment a;
        a.mimeType = ctype.isEmpty() ? QStringLiteral("application/octet-stream") : ctype;
        a.name = filename;
        a.data = decoded;
        a.inlineImage = cdisp.contains(QStringLiteral("inline")) && a.mimeType.startsWith(QStringLiteral("image/"));
        atts->append(a);
    }
}

// Sanitize a proposed attachment filename to a safe basename.
static QString safeName(const QString &name, int idx, const QString &mimeType)
{
    QString n = name;
    n.replace('/', '_').replace('\\', '_');
    n = n.section('/', -1);
    if (n.trimmed().isEmpty()) {
        QString ext = mimeType.section('/', 1, 1);
        if (ext.isEmpty()) ext = QStringLiteral("bin");
        n = QStringLiteral("attachment-%1.%2").arg(idx).arg(ext);
    }
    return n;
}

// Turn gpg's stderr signature lines into a human note. Returns "" when the
// message carries no signature at all.
static QString signatureNote(const QByteArray &errRaw)
{
    const QString e = QString::fromUtf8(errRaw);
    int g = e.indexOf(QLatin1String("Good signature from"));
    if (g >= 0)
        return e.mid(g).section('\n', 0, 0).trimmed();
    if (e.contains(QLatin1String("BAD signature")))
        return QStringLiteral("⚠ BAD signature — do not trust this message!");
    if (e.contains(QLatin1String("Can't check signature"))
        || e.contains(QLatin1String("No public key")))
        return QStringLiteral("Signed, but the signer's public key is missing — cannot verify.");
    if (e.contains(QLatin1String("Signature made")))
        return QStringLiteral("Signed (signature present).");
    return QString();
}

void GpgEngine::decryptMimeFile(const QString &pathOrUrl, const QString &passphrase)
{
    QString path = pathOrUrl;
    if (path.startsWith(QStringLiteral("file://")))
        path = path.mid(7);

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        emit decryptMimeFinished(false, QString(), QString(), QVariantList(),
                                 QStringLiteral("Cannot open encrypted part"));
        return;
    }
    const QByteArray raw = f.readAll();
    f.close();

    // The part normally is the armored block itself; extract it defensively.
    int begin = raw.indexOf("-----BEGIN PGP MESSAGE-----");
    QByteArray block = (begin >= 0) ? raw.mid(begin) : raw;

    bool tok = false;
    const QString encTmp = writeTemp(block, &tok);
    if (!tok) {
        emit decryptMimeFinished(false, QString(), QString(), QVariantList(),
                                 QStringLiteral("temp write failed"));
        return;
    }

    QStringList args;
    args << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
         << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
         << QStringLiteral("--decrypt") << QStringLiteral("--output") << QStringLiteral("-") << encTmp;

    QByteArray out, err;
    runGpg(args, passphrase.toUtf8() + "\n", &out, &err);
    QFile::remove(encTmp);
    // Success is judged by ACTUAL OUTPUT, not gpg's exit code: gpg returns a
    // non-zero status when it cannot VERIFY an embedded signature (signer's key
    // missing), even though decryption itself succeeded and produced plaintext.
    if (out.isEmpty()) {
        emit decryptMimeFinished(false, QString(), QString(), QVariantList(), friendlyGpgError(err));
        return;
    }

    const QString signedBy = signatureNote(err);

    // Fully parse the inner MIME: body text + every attachment (size-bounded unless
    // the user just lifted the limit for this load).
    QString text;
    QList<MimeAttachment> atts;
    MimeBudget budget;
    budget.unlimited = sizeLimitLifted();
    walkMime(out, &text, &atts, 0, &budget);
    if (budget.truncated) {
        text.append(QStringLiteral("\n\n[Some content was skipped because it exceeded the size limit.]"));
        emit oversizedContent();   // let the UI offer a one-time "load without limit"
    }

    // Write decrypted attachments into a fresh private cache so QML can open
    // them. Cleared each time to avoid accumulating plaintext on disk.
    const QString cacheDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                             + QStringLiteral("/decrypted");
    QDir cd(cacheDir);
    if (cd.exists())
        for (const QString &old : cd.entryList(QDir::Files))
            cd.remove(old);
    QDir().mkpath(cacheDir);

    QVariantList attList;
    for (int i = 0; i < atts.size(); ++i) {
        const MimeAttachment &a = atts[i];
        const QString name = safeName(a.name, i, a.mimeType);
        const QString outPath = cacheDir + QStringLiteral("/") + name;
        QFile af(outPath);
        if (af.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            af.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
            af.write(a.data);
            af.close();
        }
        QVariantMap m;
        m[QStringLiteral("name")] = name;
        m[QStringLiteral("mimeType")] = a.mimeType;
        m[QStringLiteral("path")] = outPath;
        m[QStringLiteral("url")] = QStringLiteral("file://") + outPath;
        m[QStringLiteral("isImage")] = a.mimeType.startsWith(QStringLiteral("image/"));
        m[QStringLiteral("size")] = a.data.size();
        attList.append(m);
        qWarning() << "[mime] decrypted attachment" << name << a.mimeType << a.data.size() << "bytes";
    }

    emit decryptMimeFinished(true, text.trimmed(), signedBy, attList, QString());
}

void GpgEngine::decryptText(const QString &armored, const QString &passphrase)
{
    bool tok = false;
    const QString encTmp = writeTemp(armored.toUtf8(), &tok);  // ciphertext: not sensitive
    if (!tok) { emit decryptFinished(false, QString(), QString(), QStringLiteral("temp write failed")); return; }

    QStringList args;
    args << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
         << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
         << QStringLiteral("--decrypt") << QStringLiteral("--output") << QStringLiteral("-") << encTmp;

    QByteArray out, err;
    runGpg(args, passphrase.toUtf8() + "\n", &out, &err);
    QFile::remove(encTmp);
    // Judge by output, not exit code — see decryptMimeFile() for why.
    if (!out.isEmpty())
        emit decryptFinished(true, QString::fromUtf8(out), signatureNote(err), QString());
    else
        emit decryptFinished(false, QString(), QString(), friendlyGpgError(err));
}

// --- PGP/MIME sending via QMF ----------------------------------------------

// Normalize a UTF-8 text body to CRLF line endings (RFC 5322 / MIME).
static QByteArray toCrlf(const QByteArray &in)
{
    QByteArray b = in;
    b.replace("\r\n", "\n");
    b.replace('\n', "\r\n");
    return b;
}

// Assemble the inner MIME entity that will be encrypted as a whole: the body
// text plus every attachment. With no attachments it's a single text/plain
// entity; otherwise multipart/mixed.
static QByteArray buildInnerMime(const QString &bodyText, const QVariantList &attachments, qint64 stamp)
{
    const QByteArray CRLF = "\r\n";
    if (attachments.isEmpty()) {
        QByteArray m;
        m += "Content-Type: text/plain; charset=utf-8" + CRLF;
        m += "Content-Transfer-Encoding: 8bit" + CRLF;
        m += CRLF;
        m += toCrlf(bodyText.toUtf8());
        if (!m.endsWith(CRLF)) m += CRLF;
        return m;
    }

    const QByteArray bnd = "sfmail-inner-" + QByteArray::number(stamp);
    QByteArray m;
    m += "Content-Type: multipart/mixed; boundary=\"" + bnd + "\"" + CRLF;
    m += "MIME-Version: 1.0" + CRLF;
    m += CRLF;

    // body text part
    m += "--" + bnd + CRLF;
    m += "Content-Type: text/plain; charset=utf-8" + CRLF;
    m += "Content-Transfer-Encoding: 8bit" + CRLF;
    m += CRLF;
    m += toCrlf(bodyText.toUtf8());
    if (!m.endsWith(CRLF)) m += CRLF;

    // attachment parts (base64, 76-char wrapped)
    for (const QVariant &v : attachments) {
        const QVariantMap a = v.toMap();
        QString path = a.value(QStringLiteral("path")).toString();
        if (path.isEmpty()) path = a.value(QStringLiteral("url")).toString();
        if (path.startsWith(QStringLiteral("file://"))) path = path.mid(7);
        QFile af(path);
        if (!af.open(QIODevice::ReadOnly)) {
            qWarning() << "[mime] send: cannot read attachment" << path;
            continue;
        }
        const QByteArray data = af.readAll();
        af.close();
        QByteArray name = a.value(QStringLiteral("name")).toString().toUtf8();
        if (name.isEmpty()) name = QFileInfo(path).fileName().toUtf8();
        QByteArray mime = a.value(QStringLiteral("mimeType")).toString().toUtf8();
        if (mime.isEmpty()) mime = "application/octet-stream";

        m += "--" + bnd + CRLF;
        m += "Content-Type: " + mime + "; name=\"" + name + "\"" + CRLF;
        m += "Content-Transfer-Encoding: base64" + CRLF;
        m += "Content-Disposition: attachment; filename=\"" + name + "\"" + CRLF;
        m += CRLF;
        const QByteArray b64 = data.toBase64();
        for (int i = 0; i < b64.size(); i += 76) { m += b64.mid(i, 76); m += CRLF; }
    }
    m += "--" + bnd + "--" + CRLF;
    return m;
}

void GpgEngine::sendPgpMime(int accountId, const QString &subject,
                            const QStringList &to, const QStringList &cc,
                            const QStringList &bcc, const QString &bodyText,
                            const QVariantList &attachments,
                            const QStringList &recipientFingerprints,
                            const QString &signFingerprint, const QString &passphrase)
{
    if (recipientFingerprints.isEmpty()) {
        emit sendFinished(false, QStringLiteral("No recipient key — cannot encrypt."));
        return;
    }

    // 1. Inner MIME entity → 2. encrypt it as a whole.
    const qint64 stamp = QDateTime::currentMSecsSinceEpoch();
    const QByteArray inner = buildInnerMime(bodyText, attachments, stamp);
    QByteArray cipher, err;
    if (!encryptRaw(recipientFingerprints, inner, signFingerprint, passphrase, &cipher, &err)) {
        emit sendFinished(false, friendlyGpgError(err));
        return;
    }

    // 3. Build + store + transmit the message — but DEFERRED off the current
    //    call stack. sendPgpMime is invoked synchronously from QML, typically
    //    from the PassphraseDialog's `accepted` handler while a page transition
    //    is still animating. Doing the QMF work (QMailMessage construction,
    //    QMailStore::addMessage, transmit) right here, on the GUI thread, in the
    //    middle of that transition deadlocks the render/compositor → the app
    //    freezes ~95 s and lipstick kills it. Same render-freeze class as the
    //    QMailMessage-in-plugin header bug and the BusyIndicator bug.
    //    Posting it via a 0-timer lets the QML call return, the page transition
    //    finish and the engine render one clean frame; THEN the QMF work runs on
    //    an idle GUI-thread turn. Capture everything by value.
    qWarning() << "[send] encrypted ok (" << cipher.size() << "bytes); deferring QMF build, accountId=" << accountId;
    QTimer::singleShot(0, this, [this, accountId, subject, to, cc, bcc, cipher, attachments]() {
        finishPgpMimeSend(accountId, subject, to, cc, bcc, cipher, !attachments.isEmpty());
    });
}

// Runs on a fresh, idle GUI-thread turn (posted from sendPgpMime). Builds the
// outer multipart/encrypted (RFC 3156) message, stores it in the outbox and
// kicks off transmission. Must NOT run inline during a page transition.
void GpgEngine::finishPgpMimeSend(int accountId, const QString &subject,
                                  const QStringList &to, const QStringList &cc,
                                  const QStringList &bcc, const QByteArray &cipher,
                                  bool hasAttachments)
{
    const QMailAccountId accId(static_cast<quint64>(accountId));
    QMailAccount account(accId);
    const QString fromAddr = account.fromAddress().toString();
    qWarning() << "[send] building msg, account" << accountId << "from" << fromAddr;

    // Build the ENTIRE outer multipart/encrypted (RFC 3156) message as raw
    // RFC 2822 bytes and parse it in ONE shot via fromRfc2822(). This avoids the
    // incremental content-mutating QMF calls (setMessageType/setMultipartType/
    // QMailMessagePart::fromData/appendPart) — one of which blocks the GUI thread
    // forever on this device (confirmed: the first such call, setMessageType,
    // never returns → Wayland freeze → app killed). fromRfc2822 parses content
    // through a different code path; afterwards we only touch metadata.
    const QByteArray boundary = "sfmail" + QByteArray::number(cipher.size())
                              + "x" + QByteArray::number(to.size() + cc.size() + 7);
    QByteArray rfc;
    rfc += "From: " + fromAddr.toUtf8() + "\r\n";
    rfc += "To: " + to.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!cc.isEmpty())  rfc += "Cc: " + cc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!bcc.isEmpty()) rfc += "Bcc: " + bcc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    rfc += "Subject: " + subject.toUtf8() + "\r\n";
    rfc += "Date: " + QMailTimeStamp::currentDateTime().toString().toUtf8() + "\r\n";
    // Message-ID + User-Agent: a bare, header-sparse mail scores higher with spam
    // filters. Give it the standard headers a normal client emits. Domain from the
    // sender; uniqueness from the timestamp + ciphertext size (no RNG needed).
    QString fromDomain = fromAddr.section('@', 1).trimmed();
    if (fromDomain.isEmpty()) fromDomain = QStringLiteral("localhost");
    rfc += "Message-ID: <" + QByteArray::number(QDateTime::currentMSecsSinceEpoch())
         + "." + QByteArray::number(cipher.size()) + "@" + fromDomain.toUtf8() + ">\r\n";
    rfc += "User-Agent: harbour-sfmail\r\n";
    rfc += "MIME-Version: 1.0\r\n";
    rfc += "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n";
    rfc += " boundary=\"" + boundary + "\"\r\n";
    rfc += "\r\n";
    rfc += "This is an OpenPGP/MIME encrypted message (RFC 3156).\r\n\r\n";
    rfc += "--" + boundary + "\r\n";
    rfc += "Content-Type: application/pgp-encrypted\r\n";
    rfc += "Content-Description: PGP/MIME version identification\r\n\r\n";
    rfc += "Version: 1\r\n\r\n";
    rfc += "--" + boundary + "\r\n";
    rfc += "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n";
    rfc += "Content-Description: OpenPGP encrypted message\r\n";
    rfc += "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n";
    // gpg --armor emits LF-only line endings. Embedding it verbatim leaves bare
    // <LF> bytes in the part body; strict SMTP servers (Postfix >=3.9 rejects
    // bare LF by default since 2024, anti-SMTP-smuggling) reject the whole message
    // with "521 5.5.2 … bare <LF> received" — and the bad bytes are stored, so
    // even the native client can't send it. Normalize the ciphertext to CRLF.
    const QByteArray cipherCrlf = toCrlf(cipher);
    rfc += cipherCrlf;
    if (!cipherCrlf.endsWith("\r\n")) rfc += "\r\n";
    rfc += "--" + boundary + "--\r\n";

    storeAndTransmit(accId, rfc, hasAttachments);
}

// Shared tail for both PGP/MIME paths (encrypted + signed). Parse the fully-built
// RFC2822 bytes in ONE shot (fromRfc2822 — the incremental QMF setters block the
// GUI thread on this device), store in the account's outbox and transmit. QMF
// transmits the stored content VERBATIM (proven by the bare-LF bug reaching SMTP),
// so a detached signature over the exact bytes we store survives transmission.
void GpgEngine::storeAndTransmit(const QMailAccountId &accId, const QByteArray &rfc,
                                 bool hasAttachments)
{
    QMailAccount account(accId);
    QMailMessage msg = QMailMessage::fromRfc2822(rfc);
    msg.setParentAccountId(accId);
    // The sending account may have NO standard Outbox folder (e.g. an account that
    // only has Junk/Drafts/Sent/Trash/Inbox). QMF then rejects addMessage with
    // "Invalid parent folder id". Fall back to the shared local-storage folder
    // (id 1) — the QMF outbox the messageserver uses for outgoing mail. Build that
    // id NUMERICALLY: the QMailFolder::LocalStorageFolderId (PredefinedFolderId)
    // ctor tries to (re)create/resolve the folder via the messageserver and BLOCKS
    // the GUI thread forever on this device. Folder 1 already exists.
    QMailFolderId outbox = account.standardFolder(QMailFolder::OutboxFolder);
    if (!outbox.isValid()) outbox = QMailFolderId(static_cast<quint64>(1));
    msg.setParentFolderId(outbox);

    msg.setStatus(QMailMessage::Outgoing, true);
    msg.setStatus(QMailMessage::ContentAvailable, true);
    msg.setStatus(QMailMessage::Read, true);
    msg.setStatus(QMailMessage::Outbox, true);
    msg.setStatus(QMailMessage::HasAttachments, hasAttachments);

    qWarning() << "[send] parts built, calling addMessage…";
    if (!QMailStore::instance()->addMessage(&msg)) {
        emit sendFinished(false, QStringLiteral("Could not store the message in the outbox."));
        return;
    }
    qWarning() << "[send] stored msg" << msg.id().toULongLong() << "in outbox — queued";

    // The message is now safely in the outbox. Report success IMMEDIATELY so the
    // composer closes — do NOT wait for the transmit callback. That callback
    // (QMailTransmitAction::activityChanged) fires unreliably in this sandbox, so
    // waiting leaves the composer stuck on "sending…" (looks like a freeze) even
    // though the messageserver delivers the outbox message just fine (confirmed
    // via SMTP). Fire-and-forget outbox semantics, like a normal mail client.
    emit sendFinished(true, QString());

    // Trigger transmission of the account's outbox (messageserver does the actual
    // SMTP). activityChanged is kept for logging only.
    if (!m_tx) {
        m_tx = new QMailTransmitAction(this);
        connect(m_tx, &QMailTransmitAction::activityChanged, this,
                [this](QMailServiceAction::Activity a) {
            if (a == QMailServiceAction::Successful)
                qWarning() << "[send] transmit Successful";
            else if (a == QMailServiceAction::Failed)
                qWarning() << "[send] transmit Failed:" << m_tx->status().text;
        });
    }
    m_tx->transmitMessages(accId);
    qWarning() << "[send] transmit call returned";
}

// --- PGP/MIME signing (multipart/signed, RFC 3156) -------------------------

void GpgEngine::signPgpMime(int accountId, const QString &subject,
                            const QStringList &to, const QStringList &cc,
                            const QStringList &bcc, const QString &bodyText,
                            const QVariantList &attachments,
                            const QString &signFingerprint, const QString &passphrase)
{
    if (signFingerprint.isEmpty()) {
        emit sendFinished(false, QStringLiteral("No signing key."));
        return;
    }
    const qint64 stamp = QDateTime::currentMSecsSinceEpoch();
    QByteArray inner = buildInnerMime(bodyText, attachments, stamp);
    // The CRLF that terminates the inner entity belongs to the MIME boundary
    // delimiter, NOT to the signed body (RFC 1847/3156). Drop exactly one trailing
    // CRLF, then sign those canonical bytes; the verifier reconstructs the same.
    QByteArray signedInner = inner;
    if (signedInner.endsWith("\r\n")) signedInner.chop(2);

    QByteArray sig, err;
    if (!signRaw(signedInner, signFingerprint, passphrase, &sig, &err)) {
        emit sendFinished(false, friendlyGpgError(err));
        return;
    }
    qWarning() << "[sign] detached sig (" << sig.size() << "bytes); deferring QMF build, accountId=" << accountId;
    const QByteArray sigCrlf = toCrlf(sig);
    const bool hasAtt = !attachments.isEmpty();
    QTimer::singleShot(0, this, [this, accountId, subject, to, cc, bcc, signedInner, sigCrlf, hasAtt]() {
        finishSignedMimeSend(accountId, subject, to, cc, bcc, signedInner, sigCrlf, hasAtt);
    });
}

void GpgEngine::finishSignedMimeSend(int accountId, const QString &subject,
                                     const QStringList &to, const QStringList &cc,
                                     const QStringList &bcc, const QByteArray &signedInner,
                                     const QByteArray &signature, bool hasAttachments)
{
    const QMailAccountId accId(static_cast<quint64>(accountId));
    QMailAccount account(accId);
    const QString fromAddr = account.fromAddress().toString();
    qWarning() << "[sign] building msg, account" << accountId << "from" << fromAddr;

    const QByteArray boundary = "sfmail-signed-" + QByteArray::number(signedInner.size())
                              + "x" + QByteArray::number(to.size() + cc.size() + 11);
    QByteArray rfc;
    rfc += "From: " + fromAddr.toUtf8() + "\r\n";
    rfc += "To: " + to.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!cc.isEmpty())  rfc += "Cc: " + cc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!bcc.isEmpty()) rfc += "Bcc: " + bcc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    rfc += "Subject: " + subject.toUtf8() + "\r\n";
    rfc += "Date: " + QMailTimeStamp::currentDateTime().toString().toUtf8() + "\r\n";
    QString fromDomain = fromAddr.section('@', 1).trimmed();
    if (fromDomain.isEmpty()) fromDomain = QStringLiteral("localhost");
    rfc += "Message-ID: <" + QByteArray::number(QDateTime::currentMSecsSinceEpoch())
         + "." + QByteArray::number(signedInner.size()) + "s@" + fromDomain.toUtf8() + ">\r\n";
    rfc += "User-Agent: harbour-sfmail\r\n";
    rfc += "MIME-Version: 1.0\r\n";
    rfc += "Content-Type: multipart/signed; micalg=\"pgp-sha256\";\r\n";
    rfc += " protocol=\"application/pgp-signature\";\r\n";
    rfc += " boundary=\"" + boundary + "\"\r\n";
    rfc += "\r\n";
    rfc += "This is an OpenPGP/MIME signed message (RFC 3156).\r\n\r\n";
    // Part 1: the EXACT signed bytes. The CRLF after it is the boundary's, not part
    // of the signed content (we chopped it off before signing).
    rfc += "--" + boundary + "\r\n";
    rfc += signedInner;
    rfc += "\r\n";
    // Part 2: the detached signature.
    rfc += "--" + boundary + "\r\n";
    rfc += "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n";
    rfc += "Content-Description: OpenPGP digital signature\r\n";
    rfc += "Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n";
    rfc += signature;
    if (!signature.endsWith("\r\n")) rfc += "\r\n";
    rfc += "--" + boundary + "--\r\n";

    storeAndTransmit(accId, rfc, hasAttachments);
}

// --- diagnostics -----------------------------------------------------------

static QString pgpAlgoName(const QString &n)
{
    if (n == QLatin1String("1") || n == QLatin1String("2") || n == QLatin1String("3"))
        return QStringLiteral("RSA");
    if (n == QLatin1String("16") || n == QLatin1String("20")) return QStringLiteral("ElGamal");
    if (n == QLatin1String("17")) return QStringLiteral("DSA");
    if (n == QLatin1String("18")) return QStringLiteral("ECDH");
    if (n == QLatin1String("19")) return QStringLiteral("ECDSA");
    if (n == QLatin1String("22")) return QStringLiteral("EdDSA");
    return n.isEmpty() ? QStringLiteral("?") : (QStringLiteral("algo ") + n);
}

// Resolve one recipient key id against the keyring with full detail.
static QVariantMap describeRecipientKey(const QString &keyid)
{
    QVariantMap m;
    m[QStringLiteral("keyId")] = keyid;
    m[QStringLiteral("inKeyring")] = false;
    m[QStringLiteral("revoked")] = false;
    m[QStringLiteral("expired")] = false;
    m[QStringLiteral("hasSecret")] = false;
    m[QStringLiteral("uids")] = QStringList();
    m[QStringLiteral("created")] = QString();
    m[QStringLiteral("algo")] = QString();
    m[QStringLiteral("bits")] = QString();
    m[QStringLiteral("fpr")] = QString();

    QByteArray pout;
    runGpg(QStringList() << QStringLiteral("--list-keys") << QStringLiteral("--with-colons") << keyid,
           QByteArray(), &pout, nullptr, 15000);
    QStringList uids;
    for (const QByteArray &lr : pout.split('\n')) {
        const QStringList f = QString::fromUtf8(lr).split(':');
        if (f.isEmpty()) continue;
        if (f[0] == QLatin1String("pub")) {
            m[QStringLiteral("inKeyring")] = true;
            const QString v = f.value(1);
            if (v.contains('r')) m[QStringLiteral("revoked")] = true;
            if (v.contains('e')) m[QStringLiteral("expired")] = true;
            m[QStringLiteral("bits")] = f.value(2);
            m[QStringLiteral("algo")] = pgpAlgoName(f.value(3));
            const QString created = f.value(5);
            if (!created.isEmpty() && created.toUInt() > 0)
                m[QStringLiteral("created")] =
                    QDateTime::fromTime_t(created.toUInt()).date().toString(Qt::ISODate);
        } else if (f[0] == QLatin1String("fpr")) {
            if (m.value(QStringLiteral("fpr")).toString().isEmpty())
                m[QStringLiteral("fpr")] = f.value(9);
        } else if (f[0] == QLatin1String("uid")) {
            const QString u = f.value(9).trimmed();
            if (!u.isEmpty() && !uids.contains(u)) uids.append(u);
        }
    }
    m[QStringLiteral("uids")] = uids;

    QByteArray sout;
    bool okSec = runGpg(QStringList() << QStringLiteral("--list-secret-keys")
                                      << QStringLiteral("--with-colons") << keyid,
                        QByteArray(), &sout, nullptr, 15000);
    if (okSec && sout.contains("sec:")) m[QStringLiteral("hasSecret")] = true;

    QString status = QStringLiteral("valid");
    if (!m.value(QStringLiteral("inKeyring")).toBool()) status = QStringLiteral("not in keyring");
    else if (m.value(QStringLiteral("revoked")).toBool()) status = QStringLiteral("REVOKED");
    else if (m.value(QStringLiteral("expired")).toBool()) status = QStringLiteral("expired");
    m[QStringLiteral("status")] = status;
    return m;
}

QVariantMap GpgEngine::encryptionInfo(const QString &src)
{
    QVariantMap result;
    const bool looksInline = src.contains(QLatin1String("-----BEGIN PGP"));
    result[QStringLiteral("format")] = looksInline ? QStringLiteral("Inline PGP")
                                                    : QStringLiteral("PGP/MIME");
    result[QStringLiteral("found")] = false;
    result[QStringLiteral("canDecrypt")] = false;
    result[QStringLiteral("signedSeen")] = false;
    result[QStringLiteral("recipients")] = QVariantList();
    result[QStringLiteral("error")] = QString();

    QByteArray block;
    if (looksInline) {
        block = src.toUtf8();
    } else {
        QString path = src;
        if (path.startsWith(QStringLiteral("file://"))) path = path.mid(7);
        QFile f(path);
        if (f.open(QIODevice::ReadOnly)) {
            const QByteArray raw = f.readAll();
            f.close();
            int b = raw.indexOf("-----BEGIN PGP");
            block = (b >= 0) ? raw.mid(b) : raw;
        }
    }
    if (block.isEmpty()) {
        result[QStringLiteral("error")] = QStringLiteral("No PGP data found to inspect.");
        return result;
    }

    bool tok = false;
    const QString tmp = writeTemp(block, &tok);
    if (!tok) { result[QStringLiteral("error")] = QStringLiteral("temp write failed"); return result; }

    QByteArray out, err;
    runGpg(QStringList() << QStringLiteral("--list-packets") << tmp, QByteArray(), &out, &err, 15000);
    QFile::remove(tmp);
    const QByteArray packets = out + "\n" + err;

    QStringList keyIds;
    bool signedSeen = false;
    for (const QByteArray &lineRaw : packets.split('\n')) {
        const QString line = QString::fromUtf8(lineRaw);
        if (line.contains(QLatin1String("pubkey enc packet"))) {
            int k = line.indexOf(QLatin1String("keyid"));
            if (k >= 0) {
                QString id = line.mid(k + 5).trimmed().section(',', 0, 0).section(' ', 0, 0).trimmed();
                if (!id.isEmpty() && !keyIds.contains(id)) keyIds.append(id);
            }
        } else if (line.contains(QLatin1String("signature packet"))) {
            signedSeen = true;
        }
    }
    result[QStringLiteral("signedSeen")] = signedSeen;
    result[QStringLiteral("found")] = !keyIds.isEmpty();

    QVariantList recips;
    bool canDecrypt = false;
    for (const QString &id : keyIds) {
        QVariantMap r = describeRecipientKey(id);
        if (r.value(QStringLiteral("hasSecret")).toBool()) canDecrypt = true;
        recips.append(r);
    }
    result[QStringLiteral("recipients")] = recips;
    result[QStringLiteral("canDecrypt")] = canDecrypt;
    return result;
}

QString GpgEngine::messageHeaders(int messageId)
{
    qWarning() << "[hdr] messageHeaders id=" << messageId;
    QMailMessageId mid(static_cast<quint64>(messageId));
    if (!mid.isValid())
        return QStringLiteral("(No valid message id.)");

    // Build from the parsed header fields rather than toRfc2822(): serializing
    // a not-fully-downloaded message can dereference an absent body and crash.
    QMailMessage m(mid);
    const QList<QMailMessageHeaderField> fields = m.headerFields();
    qWarning() << "[hdr] header fields:" << fields.size();

    // Build a SAFE-to-render header dump. The scene-graph render thread hangs on
    // certain header content (long DKIM/ARC lines, and exotic glyphs from decoded
    // From/Subject fields). So: restrict to printable ASCII (no font fallback /
    // complex shaping), collapse newlines, cap each line and the total length.
    // Whitelist of the headers worth inspecting. Rendering the FULL header set
    // (with multi-kB DKIM/ARC/X-SG blobs) as one big text block stalls this
    // device's scene-graph render thread, so we keep it small & curated.
    // NB: QMailMessageHeaderField::toString(…,presentable=false) hangs on some
    // fields (observed on Return-Path) — use id()+content() (plain accessors).
    static const QSet<QString> kWanted = {
        QStringLiteral("from"), QStringLiteral("to"), QStringLiteral("cc"),
        QStringLiteral("bcc"), QStringLiteral("reply-to"), QStringLiteral("sender"),
        QStringLiteral("subject"), QStringLiteral("date"), QStringLiteral("message-id"),
        QStringLiteral("in-reply-to"), QStringLiteral("references"),
        QStringLiteral("return-path"), QStringLiteral("content-type"),
        QStringLiteral("mime-version"), QStringLiteral("x-mailer"),
        QStringLiteral("user-agent"), QStringLiteral("received-spf"),
        QStringLiteral("authentication-results"), QStringLiteral("list-unsubscribe")
    };
    const int kMaxLine = 160;
    QString out;
    for (int fi = 0; fi < fields.size(); ++fi) {
        const QByteArray id = fields[fi].id();
        if (!kWanted.contains(QString::fromLatin1(id).toLower())) continue;
        QByteArray raw = id + ": " + fields[fi].content();
        const int n = qMin(raw.size(), kMaxLine);
        QString line;
        line.reserve(n);
        for (int k = 0; k < n; ++k) {
            const unsigned char u = static_cast<unsigned char>(raw.at(k));
            if (u == '\n' || u == '\r' || u == '\t') line += ' ';
            else if (u >= 32 && u < 127) line += QChar(u);   // printable ASCII only
            else line += '.';                                // sanitise everything else
        }
        line = line.trimmed();
        if (line.isEmpty()) continue;
        if (raw.size() > n) line += QStringLiteral(" [+%1]").arg(raw.size() - n);
        // Hard-wrap into <=40-char physical lines. A long line WITHOUT spaces
        // (Message-ID, DKIM token, …) cannot be word-wrapped by the Text element
        // and renders as one giant glyph run that stalls the render thread.
        const int kWrap = 40;
        for (int p = 0; p < line.length(); p += kWrap)
            out += line.mid(p, kWrap) + QLatin1Char('\n');
    }
    qWarning() << "[hdr] built" << out.length() << "chars";
    if (out.trimmed().isEmpty())
        return QStringLiteral("(No headers available yet — open 'Download full message' first.)");
    return out;
}

// --- "verified signed" memory (persisted) ----------------------------------

static QString signedStorePath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/signed.ini");
}

void GpgEngine::rememberSigned(int messageId, const QString &signer)
{
    if (messageId <= 0) return;
    QSettings s(signedStorePath(), QSettings::IniFormat);
    s.setValue(QString::number(messageId),
               signer.isEmpty() ? QStringLiteral("signed") : signer);
    s.sync();
    emit signedChanged();
}

bool GpgEngine::isSigned(int messageId)
{
    if (messageId <= 0) return false;
    QSettings s(signedStorePath(), QSettings::IniFormat);
    return s.contains(QString::number(messageId));
}

QString GpgEngine::signerOf(int messageId)
{
    QSettings s(signedStorePath(), QSettings::IniFormat);
    return s.value(QString::number(messageId)).toString();
}

// --- default sending account (persisted) -----------------------------------

int GpgEngine::defaultAccountId()
{
    QSettings s(signedStorePath(), QSettings::IniFormat);
    return s.value(QStringLiteral("defaultAccountId"), 0).toInt();
}

void GpgEngine::setDefaultAccountId(int accountId)
{
    QSettings s(signedStorePath(), QSettings::IniFormat);
    if (s.value(QStringLiteral("defaultAccountId"), 0).toInt() == accountId) return;
    s.setValue(QStringLiteral("defaultAccountId"), accountId);
    s.sync();
    emit defaultAccountChanged();
}

bool GpgEngine::smimeEnabled()
{
    QSettings s(signedStorePath(), QSettings::IniFormat);
    return s.value(QStringLiteral("smimeEnabled"), false).toBool();   // opt-in
}

void GpgEngine::setSmimeEnabled(bool on)
{
    QSettings s(signedStorePath(), QSettings::IniFormat);
    if (s.value(QStringLiteral("smimeEnabled"), false).toBool() == on) return;
    s.setValue(QStringLiteral("smimeEnabled"), on);
    s.sync();
    emit smimeEnabledChanged();
}

// --- raw headers + sender reputation ---------------------------------------

// Resolve a stored message id to its on-disk RFC822 content file via the QMF
// SQLite store (read-only) — WITHOUT constructing a QMailMessage (that freezes
// the app, see memory note).
static QString messageFilePath(int messageId)
{
    const QString dbPath = QDir::homePath() + QStringLiteral("/.qmf/database/qmailstore.db");
    if (!QFileInfo::exists(dbPath)) return QString();
    const QString conn = QStringLiteral("sfmail_ro_%1").arg(messageId);
    QString path;
    {
        if (QSqlDatabase::contains(conn)) QSqlDatabase::removeDatabase(conn);
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), conn);
        db.setDatabaseName(dbPath);
        db.setConnectOptions(QStringLiteral("QSQLITE_OPEN_READONLY"));
        if (db.open()) {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("SELECT mailfile FROM mailmessages WHERE id = ?"));
            q.addBindValue(messageId);
            if (q.exec() && q.next()) {
                const QString mf = q.value(0).toString();
                const int c = mf.indexOf(QLatin1Char(':'));   // strip "qmfstoragemanager:"
                path = (c >= 0) ? mf.mid(c + 1) : mf;
            }
            db.close();
        }
    }
    QSqlDatabase::removeDatabase(conn);
    return path;
}

static QByteArray readHeaderBlock(int messageId)
{
    const QString path = messageFilePath(messageId);
    if (path.isEmpty()) return QByteArray();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QByteArray();
    const QByteArray raw = f.read(512 * 1024);   // headers sit at the top
    f.close();
    int sep = raw.indexOf("\r\n\r\n");
    if (sep < 0) sep = raw.indexOf("\n\n");
    return sep >= 0 ? raw.left(sep) : raw;
}

// Unique domains of http(s) links in a message body (for URL-reputation checks
// without any third-party scanner — we just DNSBL the domains ourselves).
static QStringList extractLinkDomains(const QByteArray &body)
{
    QStringList domains;
    const QString s = QString::fromUtf8(body);
    QRegExp re(QStringLiteral("https?://([A-Za-z0-9.\\-]+)"));
    int pos = 0;
    while ((pos = re.indexIn(s, pos)) >= 0) {
        QString d = re.cap(1).toLower();
        while (d.endsWith(QLatin1Char('.'))) d.chop(1);
        // keep only real domains (a dot, not an IP literal is fine too)
        if (!d.isEmpty() && d.contains(QLatin1Char('.')) && !domains.contains(d))
            domains << d;
        pos += re.matchedLength();
        if (domains.size() >= 20) break;
    }
    return domains;
}

QString GpgEngine::rawHeaders(int messageId)
{
    const QByteArray block = readHeaderBlock(messageId);
    if (block.isEmpty())
        return QStringLiteral("(Could not read the raw headers for this message.)");
    QString out;
    const QString unf = unfoldHeaders(block);   // one logical header per line
    for (const QString &lineRaw : unf.split('\n')) {
        QString line;
        for (QChar ch : lineRaw) {
            const ushort u = ch.unicode();
            if (u == '\t') line += QLatin1Char(' ');
            else if (u >= 32 && u < 127) line += ch;
            else line += QLatin1Char('.');
        }
        line = line.trimmed();
        if (line.isEmpty()) continue;
        for (int p = 0; p < line.length(); p += 40)   // hard-wrap (safe render)
            out += line.mid(p, 40) + QLatin1Char('\n');
    }
    return out;
}

static QString emailIn(const QString &headerVal)
{
    int lt = headerVal.indexOf(QLatin1Char('<'));
    int gt = headerVal.indexOf(QLatin1Char('>'), lt + 1);
    if (lt >= 0 && gt > lt) return headerVal.mid(lt + 1, gt - lt - 1).trimmed();
    QRegExp re(QStringLiteral("[\\w.+%-]+@[\\w.-]+"));
    if (re.indexIn(headerVal) >= 0) return re.cap(0);
    return headerVal.trimmed();
}
static QString domainOf(const QString &addr)
{
    const int at = addr.lastIndexOf(QLatin1Char('@'));
    if (at < 0) return QString();
    return addr.mid(at + 1).section(QRegExp(QStringLiteral("[ >;\"]")), 0, 0).toLower();
}
static QString authKv(const QString &s, const QString &key)
{
    const int p = s.indexOf(key);
    if (p < 0) return QString();
    QString rest = s.mid(p + key.length()).trimmed();
    int e = rest.length();
    for (int i = 0; i < rest.length(); ++i) {
        const QChar c = rest[i];
        if (c == ' ' || c == ';' || c == '(' || c == ',') { e = i; break; }
    }
    return rest.left(e);
}

QVariantMap GpgEngine::analyzeSender(int messageId)
{
    QVariantMap m;
    const QByteArray block = readHeaderBlock(messageId);
    m[QStringLiteral("rawText")] = rawHeaders(messageId);
    if (block.isEmpty()) { m[QStringLiteral("error")] = QStringLiteral("no headers"); return m; }

    const QString h = unfoldHeaders(block);
    const QString fromEmail = emailIn(headerValue(h, QStringLiteral("from")));
    const QString fromDomain = domainOf(fromEmail);
    const QString returnPath = emailIn(headerValue(h, QStringLiteral("return-path")));
    const QString rpDomain = domainOf(returnPath);

    const QString ar = headerValue(h, QStringLiteral("authentication-results")).toLower();
    QString spf = authKv(ar, QStringLiteral("spf="));
    QString dkim = authKv(ar, QStringLiteral("dkim="));
    QString dmarc = authKv(ar, QStringLiteral("dmarc="));
    if (spf.isEmpty()) {
        const QString rs = headerValue(h, QStringLiteral("received-spf")).toLower();
        if (!rs.isEmpty()) spf = rs.section(QLatin1Char(' '), 0, 0);
    }

    const QString recv = headerValue(h, QStringLiteral("received"));   // topmost = sender hop
    QString originIp, originHost;
    QRegExp ipRe(QStringLiteral("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"));
    if (ipRe.indexIn(recv) >= 0) originIp = ipRe.cap(1);
    QRegExp fromRe(QStringLiteral("from\\s+([A-Za-z0-9.\\-]+)"));
    if (fromRe.indexIn(recv) >= 0) originHost = fromRe.cap(1);

    m[QStringLiteral("from")] = fromEmail;
    m[QStringLiteral("fromDomain")] = fromDomain;
    m[QStringLiteral("returnPath")] = returnPath;
    m[QStringLiteral("returnPathDomain")] = rpDomain;
    m[QStringLiteral("spf")] = spf;
    m[QStringLiteral("dkim")] = dkim;
    m[QStringLiteral("dmarc")] = dmarc;
    // DKIM signing domain (d=) — for DMARC alignment + the active check.
    QString dkimDomain;
    const QString dkimSig = headerValue(h, QStringLiteral("dkim-signature"));
    for (const QString &tok : dkimSig.split(QLatin1Char(';'))) {
        const QString tt = tok.trimmed();
        if (tt.startsWith(QStringLiteral("d="), Qt::CaseInsensitive)) {
            dkimDomain = tt.mid(2).trimmed().toLower(); break;
        }
    }
    m[QStringLiteral("dkimDomain")] = dkimDomain;
    m[QStringLiteral("originIp")] = originIp;
    m[QStringLiteral("originHost")] = originHost;
    m[QStringLiteral("mismatch")] = (!fromDomain.isEmpty() && !rpDomain.isEmpty()
                                     && fromDomain != rpDomain);

    // Link domains from the body (for URL-reputation via DNSBL). Encrypted mails
    // have ciphertext bodies → no URLs found, which is fine.
    QStringList linkDomains;
    const QString path = messageFilePath(messageId);
    if (!path.isEmpty()) {
        QFile bf(path);
        if (bf.open(QIODevice::ReadOnly)) {
            const QByteArray all = bf.read(1024 * 1024);
            bf.close();
            int sep = all.indexOf("\r\n\r\n"); int sl = 4;
            if (sep < 0) { sep = all.indexOf("\n\n"); sl = 2; }
            linkDomains = extractLinkDomains(sep >= 0 ? all.mid(sep + sl) : all);
        }
    }
    m[QStringLiteral("linkDomains")] = linkDomains;
    m[QStringLiteral("error")] = QString();
    return m;
}

void GpgEngine::checkBlacklists(const QString &ip, const QString &domain, const QStringList &linkDomains)
{
    QList<QPair<QString, QString>> queries;   // (display name, DNS name)
    if (!ip.isEmpty()) {
        const QStringList o = ip.split(QLatin1Char('.'));
        if (o.size() == 4) {
            const QString rev = o[3] + "." + o[2] + "." + o[1] + "." + o[0];
            queries << qMakePair(QStringLiteral("Spamhaus ZEN (IP)"), rev + ".zen.spamhaus.org");
            queries << qMakePair(QStringLiteral("SpamCop (IP)"), rev + ".bl.spamcop.net");
            queries << qMakePair(QStringLiteral("Barracuda (IP)"), rev + ".b.barracudacentral.org");
        }
    }
    auto addDomain = [&queries](const QString &d, const QString &label) {
        queries << qMakePair(label + QStringLiteral(" @ Spamhaus DBL"), d + ".dbl.spamhaus.org");
        queries << qMakePair(label + QStringLiteral(" @ SURBL"), d + ".multi.surbl.org");
        queries << qMakePair(label + QStringLiteral(" @ URIBL"), d + ".multi.uribl.com");
    };
    if (!domain.isEmpty()) addDomain(domain, QStringLiteral("Domain ") + domain);
    int linkCount = 0;
    for (const QString &ld : linkDomains) {
        if (ld.compare(domain, Qt::CaseInsensitive) == 0) continue;   // already done
        addDomain(ld, QStringLiteral("Link ") + ld);
        if (++linkCount >= 6) break;   // cap
    }
    m_blPending = queries.size();
    if (m_blPending == 0) { emit blacklistDone(); return; }

    for (const auto &qp : queries) {
        QDnsLookup *l = new QDnsLookup(QDnsLookup::A, qp.second, this);
        const QString name = qp.first;
        connect(l, &QDnsLookup::finished, this, [this, l, name]() {
            QString status, detail;
            if (l->error() == QDnsLookup::NoError && !l->hostAddressRecords().isEmpty()) {
                status = QStringLiteral("listed");
                QStringList a;
                for (const QDnsHostAddressRecord &r : l->hostAddressRecords())
                    a << r.value().toString();
                detail = a.join(QStringLiteral(", "));
            } else if (l->error() == QDnsLookup::NotFoundError) {
                status = QStringLiteral("clean");
                detail = QStringLiteral("not listed");
            } else {
                status = QStringLiteral("unknown");
                detail = l->errorString();
            }
            emit blacklistResult(name, status, detail);
            l->deleteLater();
            if (--m_blPending == 0) emit blacklistDone();
        });
        l->lookup();
    }
}

// --- active SPF + DMARC verification (DNS only) -----------------------------

static bool ipInCidr(const QString &ipStr, const QString &cidr)
{
    const QHostAddress ip(ipStr);
    if (ip.isNull()) return false;
    if (cidr.contains(QLatin1Char('/'))) {
        const QStringList p = cidr.split(QLatin1Char('/'));
        const QHostAddress net(p.value(0));
        bool ok = false; const int bits = p.value(1).toInt(&ok);
        if (net.isNull() || !ok) return false;
        return ip.isInSubnet(net, bits);
    }
    const QHostAddress single(cidr);
    return !single.isNull() && single == ip;
}

static QString orgDomain(const QString &d)
{
    const QStringList p = d.toLower().split(QLatin1Char('.'), QString::SkipEmptyParts);
    if (p.size() <= 2) return d.toLower();
    return p.at(p.size() - 2) + QLatin1Char('.') + p.at(p.size() - 1);
}

static QString txtStarting(QDnsLookup *l, const QString &prefix)
{
    for (const QDnsTextRecord &r : l->textRecords()) {
        QByteArray joined;
        for (const QByteArray &c : r.values()) joined += c;
        const QString s = QString::fromUtf8(joined);
        if (s.startsWith(prefix, Qt::CaseInsensitive)) return s;
    }
    return QString();
}

void GpgEngine::spfDone()
{
    if (--m_spfPending <= 0) finalizeSpf();
}

void GpgEngine::spfFetchRecord(const QString &domain, bool topLevel)
{
    if (m_spfBudget-- <= 0) { spfDone(); return; }
    QDnsLookup *l = new QDnsLookup(QDnsLookup::TXT, domain, this);
    connect(l, &QDnsLookup::finished, this, [this, l, topLevel]() {
        if (l->error() == QDnsLookup::NoError) {
            const QString rec = txtStarting(l, QStringLiteral("v=spf1"));
            if (!rec.isEmpty()) spfEval(rec, topLevel);
        }
        l->deleteLater();
        spfDone();
    });
    l->lookup();
}

void GpgEngine::spfEval(const QString &record, bool topLevel)
{
    const QStringList toks = record.split(QRegExp(QStringLiteral("\\s+")), QString::SkipEmptyParts);
    for (const QString &raw : toks) {
        if (raw.compare(QStringLiteral("v=spf1"), Qt::CaseInsensitive) == 0) continue;
        QString t = raw;
        QChar qual = QLatin1Char('+');
        if (t.startsWith('+') || t.startsWith('-') || t.startsWith('~') || t.startsWith('?')) {
            qual = t.at(0); t = t.mid(1);
        }
        const QString lower = t.toLower();
        if (lower.startsWith(QStringLiteral("ip4:"))) {
            if (qual == QLatin1Char('+') && ipInCidr(m_spfIp, t.mid(4))) m_spfMatched = true;
        } else if (lower.startsWith(QStringLiteral("a:"))) {
            if (m_spfBudget-- > 0) {
                m_spfPending++;
                QDnsLookup *al = new QDnsLookup(QDnsLookup::A, t.mid(2), this);
                const QChar q = qual;
                connect(al, &QDnsLookup::finished, this, [this, al, q]() {
                    for (const QDnsHostAddressRecord &r : al->hostAddressRecords())
                        if (q == QLatin1Char('+') && r.value().toString() == m_spfIp) m_spfMatched = true;
                    al->deleteLater(); spfDone();
                });
                al->lookup();
            }
        } else if (lower.startsWith(QStringLiteral("include:"))) {
            const QString dom = t.mid(8);
            if (!dom.isEmpty()) { m_spfPending++; spfFetchRecord(dom, false); }
        } else if (lower.startsWith(QStringLiteral("redirect="))) {
            const QString dom = t.mid(9);
            if (!dom.isEmpty()) { m_spfPending++; spfFetchRecord(dom, true); }
        } else if (lower == QStringLiteral("all")) {
            if (topLevel) m_spfTopQualifier = QString(qual);
        }
        // mx / ptr / exists / ip6 are best-effort (not evaluated)
    }
}

void GpgEngine::finalizeSpf()
{
    if (m_spfFinalized) return;
    if (m_spfPending > 0) return;
    m_spfFinalized = true;
    QString result;
    if (m_spfMatched) result = QStringLiteral("pass");
    else if (m_spfTopQualifier == QStringLiteral("-")) result = QStringLiteral("fail");
    else if (m_spfTopQualifier == QStringLiteral("~")) result = QStringLiteral("softfail");
    else if (m_spfTopQualifier == QStringLiteral("?")) result = QStringLiteral("neutral");
    else result = QStringLiteral("none");
    m_authSpfResult = result;
    emit spfResult(result, m_spfMatched ? QStringLiteral("sender IP authorised by SPF")
                                        : QStringLiteral("IP not matched; policy is '%1all'").arg(m_spfTopQualifier));
    checkDmarc();
}

void GpgEngine::checkDmarc()
{
    if (m_authFrom.isEmpty()) { emit dmarcResult(QStringLiteral("—"), QStringLiteral("—"), QString()); return; }
    QDnsLookup *l = new QDnsLookup(QDnsLookup::TXT, QStringLiteral("_dmarc.") + m_authFrom, this);
    connect(l, &QDnsLookup::finished, this, [this, l]() {
        QString rec;
        if (l->error() == QDnsLookup::NoError) rec = txtStarting(l, QStringLiteral("v=DMARC1"));
        l->deleteLater();
        if (rec.isEmpty()) {
            emit dmarcResult(QStringLiteral("no DMARC record"), QStringLiteral("fail"),
                             QStringLiteral("This domain publishes no DMARC policy."));
            return;
        }
        QString p = authKv(rec.toLower(), QStringLiteral("p="));
        if (p.isEmpty()) p = QStringLiteral("none");
        const bool spfAligned  = !m_authMailFrom.isEmpty() && orgDomain(m_authMailFrom) == orgDomain(m_authFrom);
        const bool dkimAligned = !m_authDkim.isEmpty()     && orgDomain(m_authDkim)     == orgDomain(m_authFrom);
        QString verdict, info;
        if (m_authSpfResult == QStringLiteral("pass") && spfAligned) {
            verdict = QStringLiteral("pass");
            info = QStringLiteral("aligned via SPF");
        } else if (dkimAligned) {
            verdict = QStringLiteral("DKIM-dependent");
            info = QStringLiteral("DKIM d=%1 is aligned — passes IF the DKIM signature is valid (not verified here)").arg(m_authDkim);
        } else {
            verdict = QStringLiteral("fail");
            info = QStringLiteral("SPF=%1 aligned=%2, DKIM aligned=%3")
                   .arg(m_authSpfResult, spfAligned ? "yes" : "no", dkimAligned ? "yes" : "no");
        }
        emit dmarcResult(QStringLiteral("p=") + p, verdict, info);
    });
    l->lookup();
}

void GpgEngine::checkAuth(const QString &fromDomain, const QString &mailFromDomain,
                          const QString &originIp, const QString &dkimDomain)
{
    m_authFrom = fromDomain.toLower();
    m_authMailFrom = mailFromDomain.toLower();
    m_authDkim = dkimDomain.toLower();
    m_authSpfResult = QStringLiteral("none");

    const QString spfDom = !m_authMailFrom.isEmpty() ? m_authMailFrom : m_authFrom;
    if (!spfDom.isEmpty() && !originIp.isEmpty()) {
        m_spfIp = originIp;
        m_spfMatched = false;
        m_spfFinalized = false;
        m_spfTopQualifier = QStringLiteral("?");
        m_spfPending = 1;
        m_spfBudget = 20;
        spfFetchRecord(spfDom, true);
    } else {
        emit spfResult(QStringLiteral("none"), QStringLiteral("no sender domain/IP to check"));
        checkDmarc();
    }
}
