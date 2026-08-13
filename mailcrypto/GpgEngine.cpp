#include "GpgEngine.h"

#include <QtConcurrent>
#include <QVector>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStandardPaths>
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
#include <qmailfolderkey.h>
#include <qmailmessagekey.h>
#include <qmailstore.h>
#include <qmailserviceaction.h>
#include <qmailtimestamp.h>
#include <qmailaddress.h>

// GpgME++ / QGpgME — the official C++ and Qt bindings of the GnuPG library
// (no raw gpgme C API in this file). All OpenPGP operations go through them:
// in-memory data buffers, typed results, loopback passphrase provider via the
// PassphraseProvider interface; gpg is never invoked as a child process by
// this code. GPGME itself spawns the bundled gpg below as its engine — that
// is its architecture.
#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/key.h>
#include <gpgme++/global.h>
#include <gpgme++/gpgmepp_version.h>
#include <gpgme++/keylistresult.h>
#include <gpgme++/keygenerationresult.h>
#include <gpgme++/importresult.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/verificationresult.h>
#include <gpgme++/signingresult.h>
#include <gpgme++/encryptionresult.h>
#include <gpgme++/interfaces/passphraseprovider.h>
#include <qgpgme/protocol.h>
#include <qgpgme/job.h>
#include <qgpgme/encryptjob.h>
#include <qgpgme/signencryptjob.h>
#include <qgpgme/signjob.h>
#include <qgpgme/decryptverifyjob.h>
#include <qgpgme/verifyopaquejob.h>
#include <qgpgme/importjob.h>
#include <qgpgme/keylistjob.h>
#include <gpg-error.h>   // GPG_ERR_* codes for the friendly error mapping
// The ONE raw-C GPGME call we still make: a GLOBAL engine-info bootstrap in the
// ctor. GpgME++ 1.18 exposes only a getter (GpgME::engineInfo), no global
// setter — and our bundled libgpgme has a compiled-in default gpg path
// (…-sfmail-pgp/bin/gpg, from the stack's --prefix) that does NOT exist at
// runtime (we relocate the bundle to …-sfmail/gpg). Without pinning the engine
// globally, checkEngine() fails and every fresh context/job inherits the broken
// default → decrypt fails, then crashes. Per-context overrides alone are not
// enough. This is library configuration, not a crypto operation.
#include <gpgme.h>
#include <locale.h>
#include <QRegularExpression>
#include <QUuid>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// Modern bundled GnuPG 2.2 stack, shipped under OUR OWN app prefix so the
// sandbox (which hides other apps' /usr/share/<app>) can see it.
static const char *kStackBin = "/usr/share/harbour-sfmail/gpg/bin";
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

    // gpg.conf: the bundled gpg's RPATH points at the old -pgp prefix, and its
    // compiled-in agent path likewise — pin the agent to OUR bundled binary.
    // (Previously passed per-invocation as --agent-program; with GPGME the gpg
    // command line is not ours to build, so the config file carries it.)
    QFile gc(home + QStringLiteral("/gpg.conf"));
    if (gc.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        gc.write(QByteArray("agent-program ") + kAgent + "\n");
        gc.close();
    }

    // Environment for GPGME and the gpg/gpg-agent processes it spawns: the
    // bundled binaries' RPATH points at the absent -pgp prefix, so they need
    // LD_LIBRARY_PATH (children read the environment fresh at exec time); PATH
    // lets GPGME find the bundled gpgconf for engine discovery. Set BEFORE any
    // GPGME call. (In-process resolution of libgpgme itself goes through this
    // plugin's DT_RPATH — LD_LIBRARY_PATH cannot affect an already-running
    // loader.)
    const QByteArray oldLlp = qgetenv("LD_LIBRARY_PATH");
    qputenv("LD_LIBRARY_PATH", oldLlp.isEmpty() ? QByteArray(kLibDir)
                                                : QByteArray(kLibDir) + ":" + oldLlp);
    qputenv("PATH", QByteArray(kStackBin) + ":" + qgetenv("PATH"));
    qputenv("GNUPGHOME", home.toUtf8());

    // Pin the OpenPGP engine to OUR bundled gpg + keyring home, GLOBALLY, before
    // any context is created. Without this, checkEngine() and every fresh
    // context/job fall back to libgpgme's compiled-in default gpg path (the
    // absent -pgp prefix) → decrypt fails then crashes. GpgME++ 1.18 has no
    // global setter, so this one raw-C call remains (see the <gpgme.h> note).
    GpgME::initializeLibrary();
    GpgME::setDefaultLocale(LC_CTYPE, setlocale(LC_CTYPE, nullptr));
    const QByteArray homeUtf8 = home.toUtf8();
    gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, kGpg, homeUtf8.constData());
    m_available = QFileInfo::exists(QString::fromUtf8(kGpg))
                  && !GpgME::checkEngine(GpgME::OpenPGP);
    qWarning() << "[gpg] gpgme++" << GPGMEPP_VERSION_STRING << "engine" << kGpg
               << "available=" << m_available;

    // --- DIAGNOSTIC (0.3.80 + 0.3.87): trace the send lifecycle at the QMF store
    // level — INDEPENDENT of which send path ran (plain mail goes through Nemo.Email,
    // not our engine, so logging in our send code would miss it). A user reports that
    // after sending on a POP3 account the message shows up in several folders at once
    // (drafts/sent/trash/outbox). These listeners show where a sent message lands and
    // whether it moves (outbox→sent) or stays stuck. All loads are metadata-only
    // (QMailMessageMetaData), never a full QMailMessage(id) which would freeze the GUI
    // (see memory qmailmessage-im-plugin-friert-app-ein). Filtered to OUTGOING mail so
    // an inbox sync does not flood the log. Toggle via About → Diagnostics.
    if (QMailStore *st = QMailStore::instance()) {
        const quint64 outMask = QMailMessage::Outgoing | QMailMessage::Sent
                              | QMailMessage::Outbox | QMailMessage::Draft;
        connect(st, &QMailStore::messagesRemoved, this,
                [](const QMailMessageIdList &ids) {
            QStringList s;
            for (const QMailMessageId &id : ids) s << QString::number(id.toULongLong());
            qWarning() << "[diag] msgRemoved n=" << ids.size() << "ids=" << s.join(QStringLiteral(","));
        });
        connect(st, &QMailStore::messagesAdded, this,
                [outMask](const QMailMessageIdList &ids) {
            for (const QMailMessageId &id : ids) {
                QMailMessageMetaData m(id);
                if (!(m.status() & outMask)) continue;   // skip incoming (avoid flood)
                qWarning() << "[diag] msgAdded id=" << id.toULongLong()
                           << "folder=" << m.parentFolderId().toULongLong()
                           << "acct=" << m.parentAccountId().toULongLong()
                           << "status=0x" + QString::number(m.status(), 16);
            }
        });
        // Folder/status changes: trace a message moving (outbox→sent) or staying put.
        // Filter to in-flight mail (Outgoing/Outbox/Draft) — NOT plain Sent, which
        // would re-log every sent message on each sync. Use messagesUpdated (ID list)
        // rather than messageDataUpdated: same simple signature as Added/Removed, and
        // it connects cleanly on Qt 5.6.
        const quint64 moveMask = QMailMessage::Outgoing | QMailMessage::Outbox | QMailMessage::Draft;
        connect(st, &QMailStore::messagesUpdated, this,
                [moveMask](const QMailMessageIdList &ids) {
            for (const QMailMessageId &id : ids) {
                QMailMessageMetaData m(id);
                if (!(m.status() & moveMask)) continue;
                qWarning() << "[diag] msgUpdated id=" << id.toULongLong()
                           << "folder=" << m.parentFolderId().toULongLong()
                           << "status=0x" + QString::number(m.status(), 16);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// GpgME++/QGpgME plumbing. Data stays in memory (GpgME::Data) — no plaintext
// temp files; the passphrase reaches gpg-agent through the loopback
// PassphraseProvider — no hand-built stdin piping; results and errors are
// typed — no stderr parsing.

// A MIME boundary must merely be unique and must not occur in the body. Ours used
// to be built from the app's name plus the payload size ("sfmail2479x8"), which is
// both deterministic — two mails of equal size to equally many recipients got the
// SAME boundary — and a fingerprint that identifies this client in every message
// it ever sent. Random and neutral is what every other client does.
static QByteArray mimeBoundary()
{
    return "=_" + QUuid::createUuid().toRfc4122().toHex();
}

// ---------------------------------------------------------------------------

// Passphrase for one operation, handed to GPGME's loopback machinery through
// the GpgME++ PassphraseProvider interface. The QML flow collects it in a
// dialog BEFORE the call, so the provider just hands it over (a retry after a
// wrong one → cancel instead of looping forever).
class OnePassphraseProvider : public GpgME::PassphraseProvider
{
public:
    explicit OnePassphraseProvider(const QString &pass) : m_pass(pass.toUtf8()) {}
    char *getPassphrase(const char * /*uidHint*/, const char * /*description*/,
                        bool previousWasBad, bool &canceled) override
    {
        if (previousWasBad) { canceled = true; return nullptr; }
        return strdup(m_pass.constData());   // wiped + freed by GpgME++
    }
private:
    QByteArray m_pass;
};

// Context configured for the bundled engine and our keyring; armored output;
// loopback pinentry when a passphrase provider is given.
static std::unique_ptr<GpgME::Context> makeCtx(GpgME::PassphraseProvider *pp = nullptr,
                                               bool armor = true)
{
    std::unique_ptr<GpgME::Context> ctx = GpgME::Context::create(GpgME::OpenPGP);
    if (!ctx) return ctx;
    ctx->setEngineFileName(kGpg);
    ctx->setEngineHomeDirectory(keyringHome().toUtf8().constData());
    if (armor) ctx->setArmor(true);
    if (pp) {
        ctx->setPinentryMode(GpgME::Context::PinentryLoopback);
        ctx->setPassphraseProvider(pp);
    }
    return ctx;
}

// Point a QGpgME job's context at the bundled engine/keyring (+ optional
// loopback passphrase provider). Must run BEFORE the job executes.
static void configureJob(QGpgME::Job *job, GpgME::PassphraseProvider *pp = nullptr)
{
    GpgME::Context *ctx = QGpgME::Job::context(job);
    if (!ctx) return;
    ctx->setEngineFileName(kGpg);
    ctx->setEngineHomeDirectory(keyringHome().toUtf8().constData());
    if (pp) {
        ctx->setPinentryMode(GpgME::Context::PinentryLoopback);
        ctx->setPassphraseProvider(pp);
    }
}

// Whole content of a GpgME data buffer (from the start).
static QByteArray dataToBytes(GpgME::Data &data)
{
    const std::string s = data.toString();
    return QByteArray(s.data(), static_cast<int>(s.size()));
}

static QString gpgErrString(const GpgME::Error &err)
{
    return QString::fromUtf8(err.asString());
}

// Human-friendly message for the common failures (locale-independent — mapped
// from the typed error code, not from gpg's stderr text).
static QString friendlyGpgError(const GpgME::Error &err)
{
    switch (err.code()) {
    case GPG_ERR_NO_SECKEY:
        return QStringLiteral("This message is not encrypted to your key — you are not one of its recipients.");
    case GPG_ERR_BAD_PASSPHRASE:
    case GPG_ERR_CANCELED:   // loopback provider cancels on a retry after a bad passphrase
        return QStringLiteral("Wrong passphrase.");
    case GPG_ERR_NO_DATA:
        return QStringLiteral("No PGP data found in this part.");
    default:
        return gpgErrString(err);
    }
}

// ISO date for a key/subkey timestamp (0/negative → "").
static QString keyEpochDate(long t)
{
    if (t <= 0) return QString();
    return QDateTime::fromTime_t(static_cast<uint>(t)).date().toString(Qt::ISODate);
}

// Parse a gpg expire spec ("2y", "18m"?, "0", "never", "2027-12-31") into
// seconds-from-now for Context::setExpire()/createKeyEx(). 0 = never expires.
static unsigned long expirySpecToSeconds(const QString &spec)
{
    const QString s = spec.trimmed().toLower();
    if (s.isEmpty() || s == QLatin1String("0") || s == QLatin1String("never"))
        return 0;
    QRegExp re(QStringLiteral("^(\\d+)([ymwd]?)$"));
    if (re.exactMatch(s)) {
        const qint64 n = re.cap(1).toLongLong();
        const QString u = re.cap(2);
        qint64 days = n;                       // gpg treats a bare number as days
        if (u == QLatin1String("y")) days = n * 365;
        else if (u == QLatin1String("m")) days = n * 30;
        else if (u == QLatin1String("w")) days = n * 7;
        return static_cast<unsigned long>(days * 86400);
    }
    const QDateTime dt = QDateTime::fromString(s, Qt::ISODate);
    if (dt.isValid()) {
        const qint64 secs = QDateTime::currentDateTime().secsTo(dt);
        return secs > 0 ? static_cast<unsigned long>(secs) : 0;
    }
    return 0;
}

// Primary UID ("Name <mail>") of the key with this fingerprint/keyid, "" if absent.
static QString lookupPrimaryUid(const QString &fprOrId)
{
    if (fprOrId.isEmpty()) return QString();
    std::unique_ptr<GpgME::Context> ctx = makeCtx();
    if (!ctx) return QString();
    GpgME::Error kerr;
    const GpgME::Key key = ctx->key(fprOrId.toUtf8().constData(), kerr, false);
    if (kerr || key.isNull()) return QString();
    const char *uid = key.userID(0).id();
    return uid ? QString::fromUtf8(uid) : QString();
}

// Human note for the (first) signature of a decrypt/verify result. Returns ""
// when there is no signature at all. The exact wordings are load-bearing: the
// QML colors the result by matching "Good signature"/"BAD".
static QString signatureNote(const GpgME::VerificationResult &vr)
{
    if (vr.numSignatures() == 0) return QString();
    const GpgME::Signature s = vr.signature(0);
    const QString fpr = QString::fromUtf8(s.fingerprint() ? s.fingerprint() : "");
    switch (s.status().code()) {
    case GPG_ERR_NO_ERROR: {
        const QString uid = lookupPrimaryUid(fpr);
        return uid.isEmpty()
            ? QStringLiteral("Good signature from key %1").arg(fpr.right(16))
            : QStringLiteral("Good signature from \"%1\"").arg(uid);
    }
    case GPG_ERR_BAD_SIGNATURE:
        return QStringLiteral("⚠ BAD signature — do not trust this message!");
    case GPG_ERR_NO_PUBKEY:
        return QStringLiteral("Signed, but the signer's public key is missing — cannot verify.");
    case GPG_ERR_KEY_EXPIRED:
    case GPG_ERR_SIG_EXPIRED:
    case GPG_ERR_CERT_REVOKED:
    default:
        return QStringLiteral("Signed (signature present).");
    }
}

QVariantList GpgEngine::listKeys(bool secret, const QString &pattern)
{
    QVariantList result;
    // QGpgME::openpgp() returns nullptr if the OpenPGP engine check fails —
    // dereferencing it to build a job would SIGSEGV before the !job guard. Take
    // the backend into a local and let the guard catch a null backend too.
    QGpgME::Protocol *pg = QGpgME::openpgp();
    std::unique_ptr<QGpgME::KeyListJob> job(pg ? pg->keyListJob(false) : nullptr);
    if (!job) return result;
    configureJob(job.get());
    // WithSecret flags Key::hasSecret already on the public listing, so hasSecret
    // needs no second pass over the secret keyring.
    if (GpgME::Context *ctx = QGpgME::Job::context(job.get()))
        ctx->setKeyListMode(GpgME::Local | GpgME::WithSecret);

    std::vector<GpgME::Key> keys;
    job->exec(pattern.isEmpty() ? QStringList() : QStringList(pattern), secret, keys);
    for (const GpgME::Key &key : keys) {
        const GpgME::Subkey pk = key.subkey(0);   // primary key
        if (pk.isNull()) continue;
        QVariantMap m;
        m["keyId"] = QString::fromUtf8(pk.keyID() ? pk.keyID() : "");
        m["fingerprint"] = QString::fromUtf8(pk.fingerprint() ? pk.fingerprint() : "");
        m["expired"] = key.isExpired();
        m["revoked"] = key.isRevoked();
        m["bits"] = QString::number(pk.length());
        m["algo"] = QString::fromUtf8(pk.publicKeyAlgorithmAsString());
        m["created"] = keyEpochDate(pk.creationTime());
        m["expires"] = pk.neverExpires() ? QStringLiteral("never")
                                         : keyEpochDate(pk.expirationTime());
        const GpgME::UserID u = key.userID(0);
        if (!u.isNull()) {
            m["uid"] = QString::fromUtf8(u.id() ? u.id() : "");
            m["name"] = QString::fromUtf8(u.name() ? u.name() : "");
            m["email"] = QString::fromUtf8(u.email() ? u.email() : "");
        }
        m["hasSecret"] = secret ? true : key.hasSecret();
        result.append(m);
    }
    return result;
}

QVariantList GpgEngine::publicKeys(const QString &pattern) { return listKeys(false, pattern); }
QVariantList GpgEngine::secretKeys(const QString &pattern) { return listKeys(true, pattern); }

QString GpgEngine::exportPublicKey(const QString &fingerprint)
{
    std::unique_ptr<GpgME::Context> ctx = makeCtx();
    if (!ctx) return QString();
    GpgME::Data out;
    QString result;
    if (!ctx->exportPublicKeys(fingerprint.toUtf8().constData(), out))
        result = QString::fromUtf8(dataToBytes(out));
    return result;
}

QString GpgEngine::exportSecretKey(const QString &fingerprint, const QString &passphrase)
{
    // The agent asks for the key's passphrase to re-encrypt the export; the
    // loopback provider supplies it. The exported block stays protected.
    OnePassphraseProvider pp(passphrase);
    std::unique_ptr<GpgME::Context> ctx = makeCtx(&pp);
    if (!ctx) return QString();
    GpgME::Data out;
    QString result;
    const GpgME::Error err = ctx->exportPublicKeys(fingerprint.toUtf8().constData(),
                                                   out, GpgME::Context::ExportSecret);
    if (!err) result = QString::fromUtf8(dataToBytes(out));
    else qWarning() << "[gpg] export-secret failed:" << gpgErrString(err);
    return result;
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

QString GpgEngine::stageForOpen(const QString &cachePathOrUrl,
                                const QString &suggestedName)
{
    QString src = cachePathOrUrl;
    if (src.startsWith(QStringLiteral("file://"))) src = src.mid(7);
    if (!QFileInfo::exists(src)) return QString();

    // ~/Downloads/sfmail — Downloads is whitelisted for other apps by Sailjail.
    QString dir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + QStringLiteral("/Downloads");
    dir += QStringLiteral("/sfmail");
    QDir().mkpath(dir);

    QString base = suggestedName.trimmed();
    if (base.isEmpty()) base = QFileInfo(src).fileName();
    base = base.section('/', -1).section('\\', -1);   // basename only — no traversal
    if (base.isEmpty()) base = QStringLiteral("attachment");

    const QString target = dir + QStringLiteral("/") + base;
    if (QFileInfo::exists(target)) QFile::remove(target);   // refresh, don't duplicate
    if (!QFile::copy(src, target)) return QString();
    // The private decrypted cache is owner-only (0600); make the staged copy
    // readable so the target app (a separate sandboxed process) can open it.
    QFile::setPermissions(target, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                | QFileDevice::ReadGroup | QFileDevice::ReadOther);
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
    const unsigned long secs = expirySpecToSeconds(exp);

    OnePassphraseProvider pp(passphrase);
    std::unique_ptr<GpgME::Context> ctx = makeCtx(&pp);
    if (!ctx) { emit keyOpFinished(false, QStringLiteral("GPGME context unavailable.")); return; }

    GpgME::Error kerr;
    const GpgME::Key key = ctx->key(fingerprint.toUtf8().constData(), kerr, false);
    if (kerr || key.isNull()) {
        emit keyOpFinished(false, QStringLiteral("Key not found."));
        return;
    }
    // Primary key first, then all subkeys (SetExpireAllSubkeys = gpg's "*").
    GpgME::Error err = ctx->setExpire(key, secs);
    if (!err)
        ctx->setExpire(key, secs, std::vector<GpgME::Subkey>(),
                       GpgME::Context::SetExpireAllSubkeys);

    if (!err) { emit keyOpFinished(true, QStringLiteral("Validity extended.")); emit keysChanged(); }
    else       emit keyOpFinished(false, friendlyGpgError(err));
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
    QGpgME::Protocol *pg = QGpgME::openpgp();
    std::unique_ptr<QGpgME::ImportJob> job(pg ? pg->importJob() : nullptr);
    if (!job) { emit keyOpFinished(false, QStringLiteral("GPGME context unavailable.")); return; }
    configureJob(job.get());
    const GpgME::Error err = job->exec(data).error();
    if (!err) {
        emit keyOpFinished(true, QStringLiteral("Key revoked. Publish it now so others stop using it."));
        emit keysChanged();
    } else {
        emit keyOpFinished(false, friendlyGpgError(err));
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

// Capability text of one subkey ("sign, encrypt, …").
static QString subkeyCaps(const GpgME::Subkey &sk)
{
    QStringList c;
    if (sk.canSign()) c << QStringLiteral("sign");
    if (sk.canEncrypt()) c << QStringLiteral("encrypt");
    if (sk.canCertify()) c << QStringLiteral("certify");
    if (sk.canAuthenticate()) c << QStringLiteral("authenticate");
    return c.join(QStringLiteral(", "));
}

QVariantMap GpgEngine::keyDetails(const QString &fingerprint)
{
    QVariantMap m;
    std::unique_ptr<GpgME::Context> ctx = makeCtx();
    if (!ctx) return m;
    ctx->setKeyListMode(GpgME::Local | GpgME::WithSecret);

    QStringList uids;
    QVariantList subkeys;
    bool hasSecret = false;
    GpgME::Error kerr;
    const GpgME::Key key = ctx->key(fingerprint.toUtf8().constData(), kerr, false);
    if (!kerr && !key.isNull()) {
        hasSecret = key.hasSecret();
        m[QStringLiteral("revoked")] = key.isRevoked();
        m[QStringLiteral("expired")] = key.isExpired();
        // Aggregate capabilities of the whole key (primary + subkeys).
        QStringList caps;
        if (key.canSign()) caps << QStringLiteral("sign");
        if (key.canEncrypt()) caps << QStringLiteral("encrypt");
        if (key.canCertify()) caps << QStringLiteral("certify");
        if (key.canAuthenticate()) caps << QStringLiteral("authenticate");
        m[QStringLiteral("caps")] = caps.join(QStringLiteral(", "));
        const std::vector<GpgME::Subkey> sks = key.subkeys();
        for (size_t i = 0; i < sks.size(); ++i) {
            const GpgME::Subkey &sk = sks[i];
            if (i == 0) {   // primary key → top-level fields
                m[QStringLiteral("keyId")] = QString::fromUtf8(sk.keyID() ? sk.keyID() : "");
                m[QStringLiteral("fingerprint")] = QString::fromUtf8(sk.fingerprint() ? sk.fingerprint() : "");
                m[QStringLiteral("bits")] = QString::number(sk.length());
                m[QStringLiteral("algo")] = QString::fromUtf8(sk.publicKeyAlgorithmAsString());
                m[QStringLiteral("created")] = keyEpochDate(sk.creationTime());
                m[QStringLiteral("expires")] = sk.neverExpires() ? QStringLiteral("never")
                                                                 : keyEpochDate(sk.expirationTime());
                continue;
            }
            QVariantMap s;
            s[QStringLiteral("keyId")] = QString::fromUtf8(sk.keyID() ? sk.keyID() : "");
            s[QStringLiteral("fpr")] = QString::fromUtf8(sk.fingerprint() ? sk.fingerprint() : "");
            s[QStringLiteral("bits")] = QString::number(sk.length());
            s[QStringLiteral("algo")] = QString::fromUtf8(sk.publicKeyAlgorithmAsString());
            s[QStringLiteral("created")] = keyEpochDate(sk.creationTime());
            s[QStringLiteral("expires")] = sk.neverExpires() ? QStringLiteral("never")
                                                             : keyEpochDate(sk.expirationTime());
            s[QStringLiteral("caps")] = subkeyCaps(sk);
            s[QStringLiteral("revoked")] = sk.isRevoked();
            s[QStringLiteral("expired")] = sk.isExpired();
            subkeys.append(s);
        }
        for (const GpgME::UserID &u : key.userIDs()) {
            const QString us = QString::fromUtf8(u.id() ? u.id() : "").trimmed();
            if (!us.isEmpty() && !uids.contains(us)) uids << us;
        }
    }

    m[QStringLiteral("uids")] = uids;
    m[QStringLiteral("subkeys")] = subkeys;
    m[QStringLiteral("status")] = m.value(QStringLiteral("revoked")).toBool() ? QStringLiteral("REVOKED")
                                  : m.value(QStringLiteral("expired")).toBool() ? QStringLiteral("expired")
                                  : QStringLiteral("valid");
    m[QStringLiteral("hasSecret")] = hasSecret;
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
    QGpgME::Protocol *pg = QGpgME::openpgp();
    std::unique_ptr<QGpgME::ImportJob> job(pg ? pg->importJob() : nullptr);
    if (!job) { emit importFinished(false, 0, QStringLiteral("GPGME context unavailable.")); return; }
    configureJob(job.get());
    const GpgME::ImportResult r = job->exec(armored.toUtf8());
    const GpgME::Error err = r.error();
    if (!err) {
        const int imported = r.numImported() + r.numSecretKeysImported() + r.numUnchanged();
        emit importFinished(true, imported, QString());
        emit keysChanged();
    } else {
        emit importFinished(false, 0, friendlyGpgError(err));
    }
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
    // List the keys contained in the data WITHOUT importing anything.
    GpgME::Data din(armored.constData(), static_cast<size_t>(armored.size()), false);
    QStringList us;
    for (const GpgME::Key &key : din.toKeys(GpgME::OpenPGP)) {
        const std::vector<GpgME::Subkey> sks = key.subkeys();
        for (size_t i = 0; i < sks.size(); ++i) {
            const GpgME::Subkey &sk = sks[i];
            const QString k = QString::fromUtf8(sk.keyID() ? sk.keyID() : "");
            if (!k.isEmpty()) keyIds->append(k.toUpper());
            if (i == 0 && primaryFpr->isEmpty() && sk.fingerprint())
                *primaryFpr = QString::fromUtf8(sk.fingerprint()).toUpper();
        }
        for (const GpgME::UserID &u : key.userIDs())
            if (u.id() && *u.id()) us << QString::fromUtf8(u.id());
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
    GpgME::Data din(armored.constData(), static_cast<size_t>(armored.size()), false);

    QStringList uids, emails;
    bool havePub = false;
    for (const GpgME::Key &key : din.toKeys(GpgME::OpenPGP)) {
        const GpgME::Subkey pk = key.subkey(0);
        if (havePub || pk.isNull()) continue;   // only the FIRST key block matters here
        havePub = true;
        m[QStringLiteral("keyId")] = QString::fromUtf8(pk.keyID() ? pk.keyID() : "");
        m[QStringLiteral("fpr")] = QString::fromUtf8(pk.fingerprint() ? pk.fingerprint() : "").toUpper();
        m[QStringLiteral("bits")] = QString::number(pk.length());
        m[QStringLiteral("algo")] = QString::fromUtf8(pk.publicKeyAlgorithmAsString());
        m[QStringLiteral("created")] = keyEpochDate(pk.creationTime());
        m[QStringLiteral("expires")] = pk.neverExpires() ? QStringLiteral("never")
                                                         : keyEpochDate(pk.expirationTime());
        bool expired = key.isExpired() || pk.isExpired();
        // The listing flags can lag for keys not in the keyring → also check the date.
        if (!pk.neverExpires() && pk.expirationTime() > 0
            && pk.expirationTime() < QDateTime::currentMSecsSinceEpoch() / 1000)
            expired = true;
        m[QStringLiteral("revoked")] = key.isRevoked() || pk.isRevoked();
        m[QStringLiteral("expired")] = expired;
        for (const GpgME::UserID &u : key.userIDs()) {
            const QString us = QString::fromUtf8(u.id() ? u.id() : "");
            if (us.isEmpty() || uids.contains(us)) continue;
            uids << us;
            const QString email = QString::fromUtf8(u.email() ? u.email() : "").toLower();
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
    std::unique_ptr<GpgME::Context> ctx = makeCtx();
    if (!ctx) { emit keyDeleted(false, QStringLiteral("GPGME context unavailable.")); return; }
    GpgME::Error kerr;
    const GpgME::Key key = ctx->key(fingerprint.toUtf8().constData(), kerr, false);
    if (kerr || key.isNull()) {
        emit keyDeleted(false, QStringLiteral("Key not found."));
        return;
    }
    // Secret deletion needs DeleteForce (gpg runs in batch mode → --yes); the
    // flags overload is our backport of the gpgme 1.20 C++ API (see stack build).
    const GpgME::Error err = deleteSecret
        ? ctx->deleteKey(key, static_cast<unsigned int>(GpgME::Context::DeleteAllowSecret
                                                        | GpgME::Context::DeleteForce))
        : ctx->deleteKey(key, false);
    if (!err) { emit keyDeleted(true, QString()); emit keysChanged(); }
    else       emit keyDeleted(false, friendlyGpgError(err));
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
    const unsigned long expSecs = expirySpecToSeconds(exp);

    emit keyGenStarted();

    // Key generation takes a while — run it on a worker thread so the GUI never
    // blocks. Signals emitted from the worker are auto-queued to the UI thread.
    QtConcurrent::run([this, uid, expSecs, passphrase]() {
        // Values of GPGME_CREATE_SIGN/CERT/ENCR (stable C ABI; gpgme++ 1.18 has
        // no C++ enum for the quick-keygen flags yet).
        const unsigned int kCreateSign = 1, kCreateEncr = 2, kCreateCert = 4;

        OnePassphraseProvider pp(passphrase);
        std::unique_ptr<GpgME::Context> ctx = makeCtx(&pp);
        if (!ctx) { emit keyGenFinished(false, QString(), QStringLiteral("GPGME context unavailable.")); return; }

        // Step 1 — RSA-4096 primary key, usage cert,sign.
        const GpgME::KeyGenerationResult gr =
            ctx->createKeyEx(uid.toUtf8().constData(), "rsa4096",
                             0, expSecs, GpgME::Key(), kCreateSign | kCreateCert);
        if (gr.error()) {
            emit keyGenFinished(false, QString(), friendlyGpgError(gr.error()));
            return;
        }
        const QString fpr = QString::fromUtf8(gr.fingerprint() ? gr.fingerprint() : "");
        if (fpr.isEmpty()) {
            // Primary was created but we couldn't read its fingerprint back; the
            // key exists and is usable for signing — just refresh the list.
            emit keyGenFinished(true, QString(), QString());
            emit keysChanged();
            return;
        }

        // Step 2 — add an RSA-4096 encryption subkey to the just-made primary.
        GpgME::Error err, kerr;
        const GpgME::Key key = ctx->key(fpr.toUtf8().constData(), kerr, false);
        if (!kerr && !key.isNull())
            err = ctx->createSubkey(key, "rsa4096", 0, expSecs, kCreateEncr);
        else
            err = kerr;

        if (err) {
            // Primary is fine but the encryption subkey failed — report it so
            // the user can retry adding one rather than think nothing happened.
            emit keyGenFinished(false, fpr,
                QStringLiteral("Primary key created, but adding the encryption subkey failed: ")
                + friendlyGpgError(err));
            emit keysChanged();
            return;
        }
        emit keyGenFinished(true, fpr, QString());
        emit keysChanged();
    });
}

// Synchronous encrypt (+ optional sign) of raw bytes. armored result in *out.
// Everything stays in memory (gpgme data buffers) — no plaintext temp file.
bool GpgEngine::encryptRaw(const QStringList &recipientFingerprints, const QByteArray &plaintext,
                           const QString &signFingerprint, const QString &passphrase,
                           QByteArray *out, QString *errMsg)
{
    // Resolve recipient (and signing) keys; Key objects are context-independent.
    std::unique_ptr<GpgME::Context> kctx = makeCtx();
    if (!kctx) { if (errMsg) *errMsg = QStringLiteral("GPGME context unavailable."); return false; }

    std::vector<GpgME::Key> keys;
    for (const QString &fpr : recipientFingerprints) {
        GpgME::Error kerr;
        const GpgME::Key k = kctx->key(fpr.toUtf8().constData(), kerr, false);
        if (kerr || k.isNull()) {
            if (errMsg) *errMsg = QStringLiteral("Recipient key not found.");
            return false;
        }
        keys.push_back(k);
    }

    // ALWAYS_TRUST mirrors the previous --trust-model always: the user picked
    // the recipient keys explicitly, we don't gate on web-of-trust validity.
    QByteArray cipher;
    GpgME::Error err;
    if (signFingerprint.isEmpty()) {
        QGpgME::Protocol *pg = QGpgME::openpgp();
        std::unique_ptr<QGpgME::EncryptJob> job(pg ? pg->encryptJob(/*armor=*/true, false) : nullptr);
        if (!job) { if (errMsg) *errMsg = QStringLiteral("GPGME context unavailable."); return false; }
        configureJob(job.get());
        err = job->exec(keys, plaintext, /*alwaysTrust=*/true, cipher).error();
    } else {
        GpgME::Error kerr;
        const GpgME::Key sk = kctx->key(signFingerprint.toUtf8().constData(), kerr, true);
        if (kerr || sk.isNull()) {
            if (errMsg) *errMsg = QStringLiteral("Signing key not found.");
            return false;
        }
        OnePassphraseProvider pp(passphrase);
        QGpgME::Protocol *pg = QGpgME::openpgp();
        std::unique_ptr<QGpgME::SignEncryptJob> job(pg ? pg->signEncryptJob(/*armor=*/true, false) : nullptr);
        if (!job) { if (errMsg) *errMsg = QStringLiteral("GPGME context unavailable."); return false; }
        configureJob(job.get(), &pp);
        const std::pair<GpgME::SigningResult, GpgME::EncryptionResult> r =
            job->exec(std::vector<GpgME::Key>(1, sk), keys, plaintext, /*alwaysTrust=*/true, cipher);
        err = r.first.error() ? r.first.error() : r.second.error();
    }

    const bool ok = !err;
    if (ok && out) *out = cipher;
    if (!ok && errMsg) *errMsg = friendlyGpgError(err);
    return ok;
}

void GpgEngine::encrypt(const QStringList &recipientFingerprints, const QString &plaintext,
                        const QString &signFingerprint, const QString &passphrase)
{
    QByteArray out;
    QString err;
    bool ok = encryptRaw(recipientFingerprints, plaintext.toUtf8(), signFingerprint, passphrase, &out, &err);
    if (ok) emit encryptFinished(true, QString::fromUtf8(out), QString());
    else    emit encryptFinished(false, QString(), err);
}

// Common body of signRaw/clearSign: sign `data` with the given key in `mode`.
// On success fills *out (armored) and, if wanted, *micalgOut ("pgp-sha256"-
// style, derived from the ACTUAL hash the engine used — no guessing).
static bool signWithMode(const QByteArray &data, const QString &signFingerprint,
                         const QString &passphrase, GpgME::SignatureMode mode,
                         QByteArray *out, QString *micalgOut, QString *errMsg)
{
    std::unique_ptr<GpgME::Context> kctx = makeCtx();
    if (!kctx) { if (errMsg) *errMsg = QStringLiteral("GPGME context unavailable."); return false; }
    GpgME::Error kerr;
    const GpgME::Key sk = kctx->key(signFingerprint.toUtf8().constData(), kerr, true);
    if (kerr || sk.isNull()) {
        if (errMsg) *errMsg = QStringLiteral("Signing key not found.");
        return false;
    }

    OnePassphraseProvider pp(passphrase);
    QGpgME::Protocol *pg = QGpgME::openpgp();
    std::unique_ptr<QGpgME::SignJob> job(pg ? pg->signJob(/*armor=*/true, false) : nullptr);
    if (!job) { if (errMsg) *errMsg = QStringLiteral("GPGME context unavailable."); return false; }
    configureJob(job.get(), &pp);

    QByteArray sig;
    const GpgME::SigningResult sr =
        job->exec(std::vector<GpgME::Key>(1, sk), data, mode, sig);
    const bool ok = !sr.error();
    if (ok) {
        if (out) *out = sig;
        if (micalgOut) {
            *micalgOut = QStringLiteral("pgp-sha256");   // sane fallback
            const GpgME::CreatedSignature cs = sr.createdSignature(0);
            const char *h = cs.isNull() ? nullptr : cs.hashAlgorithmAsString();
            if (h) *micalgOut = QStringLiteral("pgp-") + QString::fromUtf8(h).toLower();
        }
    } else if (errMsg) {
        *errMsg = friendlyGpgError(sr.error());
    }
    return ok && out && !out->isEmpty();
}

// Synchronous DETACHED armored signature over raw bytes; *micalgOut receives
// the RFC 3156 micalg matching the hash the engine actually used.
bool GpgEngine::signRaw(const QByteArray &data, const QString &signFingerprint,
                        const QString &passphrase, QByteArray *out,
                        QString *micalgOut, QString *errMsg)
{
    return signWithMode(data, signFingerprint, passphrase, GpgME::Detached,
                        out, micalgOut, errMsg);
}

// Inline clear-text signature, NO encryption. Result via encryptFinished() so
// the QML inline-send flow is reused unchanged.
void GpgEngine::clearSign(const QString &text, const QString &signFingerprint,
                          const QString &passphrase)
{
    QByteArray out;
    QString err;
    if (signWithMode(text.toUtf8(), signFingerprint, passphrase, GpgME::Clearsigned,
                     &out, nullptr, &err))
        emit encryptFinished(true, QString::fromUtf8(out), QString());
    else
        emit encryptFinished(false, QString(), err);
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

    OnePassphraseProvider pp(passphrase);
    QGpgME::Protocol *pg = QGpgME::openpgp();
    std::unique_ptr<QGpgME::DecryptVerifyJob> job(pg ? pg->decryptVerifyJob(false) : nullptr);
    if (!job) {
        emit decryptMimeFinished(false, QString(), QString(), QVariantList(),
                                 QStringLiteral("GPGME context unavailable."));
        return;
    }
    configureJob(job.get(), &pp);
    // The decrypt succeeds when DECRYPTION worked; an embedded signature that
    // cannot be verified (signer's key missing) is not an error — it is
    // reported separately through the verification result / signature note.
    QByteArray out;
    const std::pair<GpgME::DecryptionResult, GpgME::VerificationResult> res =
        job->exec(block, out);
    if (res.first.error()) {
        emit decryptMimeFinished(false, QString(), QString(), QVariantList(),
                                 friendlyGpgError(res.first.error()));
        return;
    }
    const QString signedBy = signatureNote(res.second);

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
    const QByteArray in = armored.toUtf8();
    OnePassphraseProvider pp(passphrase);

    // The QML also routes CLEARSIGNED-only bodies here (with an empty
    // passphrase, "signature only") — those need verify, not decrypt.
    const bool clearsigned = in.contains("-----BEGIN PGP SIGNED MESSAGE-----");
    QByteArray out;
    GpgME::Error gerr;
    GpgME::VerificationResult vr;
    if (clearsigned) {
        QGpgME::Protocol *pg = QGpgME::openpgp();
        std::unique_ptr<QGpgME::VerifyOpaqueJob> job(pg ? pg->verifyOpaqueJob(false) : nullptr);
        if (!job) { emit decryptFinished(false, QString(), QString(), QStringLiteral("GPGME context unavailable.")); return; }
        configureJob(job.get());
        vr = job->exec(in, out);
        gerr = vr.error();
    } else {
        QGpgME::Protocol *pg = QGpgME::openpgp();
        std::unique_ptr<QGpgME::DecryptVerifyJob> job(pg ? pg->decryptVerifyJob(false) : nullptr);
        if (!job) { emit decryptFinished(false, QString(), QString(), QStringLiteral("GPGME context unavailable.")); return; }
        configureJob(job.get(), &pp);
        const std::pair<GpgME::DecryptionResult, GpgME::VerificationResult> res =
            job->exec(in, out);
        gerr = res.first.error();
        vr = res.second;
    }

    if (!gerr)
        emit decryptFinished(true, QString::fromUtf8(out), signatureNote(vr), QString());
    else
        emit decryptFinished(false, QString(), QString(), friendlyGpgError(gerr));
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

    const QByteArray bnd = mimeBoundary();
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
    QByteArray cipher;
    QString err;
    if (!encryptRaw(recipientFingerprints, inner, signFingerprint, passphrase, &cipher, &err)) {
        emit sendFinished(false, err);
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
    const QByteArray boundary = mimeBoundary();
    QByteArray rfc;
    rfc += "From: " + fromAddr.toUtf8() + "\r\n";
    rfc += "To: " + to.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!cc.isEmpty())  rfc += "Cc: " + cc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!bcc.isEmpty()) rfc += "Bcc: " + bcc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    rfc += "Subject: " + subject.toUtf8() + "\r\n";
    rfc += "Date: " + QMailTimeStamp::currentDateTime().toString().toUtf8() + "\r\n";
    // Message-ID: a bare, header-sparse mail scores higher with spam filters, so
    // give it the standard headers a normal client emits. Domain from the sender;
    // uniqueness from the timestamp + ciphertext size (no RNG needed).
    QString fromDomain = fromAddr.section('@', 1).trimmed();
    if (fromDomain.isEmpty()) fromDomain = QStringLiteral("localhost");
    rfc += "Message-ID: <" + QByteArray::number(QDateTime::currentMSecsSinceEpoch())
         + "." + QByteArray::number(cipher.size()) + "@" + fromDomain.toUtf8() + ">\r\n";
    // No User-Agent: it is optional, and "harbour-sfmail" is a token no filter has
    // ever seen, which makes every message from this app individually identifiable
    // to content scoring. Dropped while chasing a provider-side 554 that hit only
    // this client while other clients on the same account went through.
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
    // No name/filename on the ciphertext part. QMF re-derives a part's Content-Type
    // when fromRfc2822() parses our bytes, and it does so from the FILE EXTENSION:
    // ".asc" became application/pgp-signature on SFOS 4.6 (libqmfclient git144) and
    // text/plain; charset=utf-8 on 5.1 (git185) — same package, two devices, measured.
    // The text/plain variant makes a multipart/encrypted whose ciphertext claims to
    // be text, which content filters score as an obfuscated payload: the provider
    // answered 554 for the 5.1 device while the identical mail from 4.6 arrived with
    // a negative spam score. Without a name there is no extension to sniff, and the
    // declared application/octet-stream (RFC 3156) has a chance to survive. Correcting
    // it afterwards through QMF's own API is NOT an option — partAt() detaches the
    // private impl and crashes in the ABI shim (tried, reproducible, see
    // qmf_abi_compat.cpp). Neither name nor filename is required by RFC 3156.
    rfc += "Content-Type: application/octet-stream\r\n";
    rfc += "Content-Description: OpenPGP encrypted message\r\n";
    rfc += "Content-Disposition: inline\r\n\r\n";
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
    // Heap-allocate and INTENTIONALLY never delete this message. Destroying a
    // QMailMessage built here via fromRfc2822 intermittently crashes (SIGSEGV) in
    // the QMF ABI-shim destructor ~immediately after addMessage/transmit — a
    // confirmed use-after-free of the message's private impl (core dump: crash in
    // ~QPrivateImplementationPointer<QMailMessageMetaDataPrivate>, calling a
    // garbage delete_function). The device's libQmfClient does not export the
    // template destructors, so we can't fix it in the shim; the same shim is fine
    // for QMailMessageMetaData(id) loaded elsewhere, so the problem is specific to
    // the store/transmit lifecycle of THIS object. Sends are infrequent, so leaking
    // one small QMailMessage per send is the safe trade-off (no destructor → no
    // UAF). C++17 guaranteed elision means no temporary is created/destroyed here.
    QMailMessage *msg = new QMailMessage(QMailMessage::fromRfc2822(rfc));

    msg->setParentAccountId(accId);
    // The sending account may have NO standard Outbox folder (e.g. an account that
    // only has Junk/Drafts/Sent/Trash/Inbox). QMF then rejects addMessage with
    // "Invalid parent folder id". Fall back to the shared local-storage folder
    // (id 1) — the QMF outbox the messageserver uses for outgoing mail. Build that
    // id NUMERICALLY: the QMailFolder::LocalStorageFolderId (PredefinedFolderId)
    // ctor tries to (re)create/resolve the folder via the messageserver and BLOCKS
    // the GUI thread forever on this device. Folder 1 already exists.
    QMailFolderId outbox = account.standardFolder(QMailFolder::OutboxFolder);
    if (!outbox.isValid()) outbox = QMailFolderId(static_cast<quint64>(1));
    msg->setParentFolderId(outbox);

    msg->setStatus(QMailMessage::Outgoing, true);
    msg->setStatus(QMailMessage::ContentAvailable, true);
    msg->setStatus(QMailMessage::Read, true);
    msg->setStatus(QMailMessage::Outbox, true);
    msg->setStatus(QMailMessage::HasAttachments, hasAttachments);

    qWarning() << "[send] parts built, calling addMessage…";
    if (!QMailStore::instance()->addMessage(msg)) {
        emit sendFinished(false, QStringLiteral("Could not store the message in the outbox."));
        return;
    }
    qWarning() << "[send] stored msg" << msg->id().toULongLong() << "in outbox — queued";

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
            else if (a == QMailServiceAction::Failed) {
                qWarning() << "[send] transmit Failed:" << m_tx->status().text;
                onTransmitFailed(m_tx->status().text);
            } else if (a == QMailServiceAction::Successful) {
                // Delivered: stop any running schedule.
                m_retryTimer.stop();
                m_retryStep = -1;
            }
        });
    }
    m_retryAccount = accId.toULongLong();
    m_tx->transmitMessages(accId);
    qWarning() << "[send] transmit call returned";
}

// --- Re-sending a stuck outbox ---------------------------------------------
//
// QMF has no per-message send: QMailTransmitAction::transmitMessages(account)
// pushes that account's whole outbox. There was no way to retry at all before —
// the app's "Sync" only ever RETRIEVES (retrieveMessageList / synchronizeInbox),
// so a message that failed once sat there until the next new mail happened to
// flush the outbox along with it.

// Minutes between automatic attempts. Deliberately finite: a server that refuses
// a message for good (5xx) will refuse it forever, and hammering it only damages
// the sender's reputation.
static const int kRetryMinutes[] = { 1, 2, 5, 10, 15, 30, 45, 60 };
static const int kRetryCount = int(sizeof(kRetryMinutes) / sizeof(kRetryMinutes[0]));

// A permanent refusal (SMTP 5xx) is not worth repeating. QMF hands us the server
// text verbatim, so look for the code the server actually sent.
static bool isPermanentFailure(const QString &err)
{
    static const QRegularExpression re(QStringLiteral("\\b5[0-9][0-9]\\b"));
    return re.match(err).hasMatch();
}

int GpgEngine::outboxCount(int accountId)
{
    QMailAccountId accId(static_cast<quint64>(accountId));
    if (!accId.isValid()) return 0;
    QMailMessageKey key(QMailMessageKey::parentAccountId(accId));
    key &= QMailMessageKey::status(QMailMessage::Outbox, QMailDataComparator::Includes);
    return QMailStore::instance()->countMessages(key);
}

bool GpgEngine::retryOutbox(int accountId)
{
    QMailAccountId accId(static_cast<quint64>(accountId));
    if (!accId.isValid()) return false;

    if (!m_tx) {
        m_tx = new QMailTransmitAction(this);
        connect(m_tx, &QMailTransmitAction::activityChanged, this,
                [this](QMailServiceAction::Activity a) {
            if (a == QMailServiceAction::Successful) {
                qWarning() << "[send] transmit Successful";
                m_retryTimer.stop();
                m_retryStep = -1;
            } else if (a == QMailServiceAction::Failed) {
                qWarning() << "[send] transmit Failed:" << m_tx->status().text;
                onTransmitFailed(m_tx->status().text);
            }
        });
    }
    qWarning() << "[send] manual retry for account" << accountId
               << "outbox holds" << outboxCount(accountId);
    m_tx->transmitMessages(accId);
    return true;
}

void GpgEngine::cancelRetries()
{
    if (m_retryStep >= 0) {
        m_retryTimer.stop();
        m_retryStep = -1;
        emit retryStopped(QStringLiteral("cancelled"));
    }
}

int GpgEngine::minutesToNextRetry()
{
    if (m_retryStep < 0 || !m_retryTimer.isActive()) return -1;
    return (m_retryTimer.remainingTime() + 59999) / 60000;
}

void GpgEngine::onTransmitFailed(const QString &error)
{
    if (isPermanentFailure(error)) {
        // The server said no, for good. Retrying cannot help and would only keep
        // re-offering a message it already judged.
        m_retryTimer.stop();
        m_retryStep = -1;
        emit retryStopped(error);
        qWarning() << "[send] permanent refusal — no automatic retry:" << error;
        return;
    }
    scheduleRetry(QMailAccountId(m_retryAccount ? m_retryAccount : 0));
}

void GpgEngine::scheduleRetry(const QMailAccountId &accId)
{
    if (accId.isValid()) m_retryAccount = accId.toULongLong();
    if (!m_retryAccount) return;

    if (++m_retryStep >= kRetryCount) {
        m_retryStep = -1;
        emit retryStopped(QStringLiteral("giving up after the last attempt"));
        qWarning() << "[send] retry schedule exhausted";
        return;
    }

    const int minutes = kRetryMinutes[m_retryStep];
    m_retryTimer.setSingleShot(true);
    m_retryTimer.disconnect();
    connect(&m_retryTimer, &QTimer::timeout, this, [this]() {
        qWarning() << "[send] automatic retry" << (m_retryStep + 1) << "of" << kRetryCount;
        retryOutbox(int(m_retryAccount));
    });
    m_retryTimer.start(minutes * 60 * 1000);
    emit retryScheduled(m_retryStep + 1, kRetryCount, minutes);
    qWarning() << "[send] next automatic retry in" << minutes << "minutes";
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

    QByteArray sig;
    QString micalg, err;
    if (!signRaw(signedInner, signFingerprint, passphrase, &sig, &micalg, &err)) {
        emit sendFinished(false, err);
        return;
    }
    qWarning() << "[sign] detached sig (" << sig.size() << "bytes," << micalg
               << "); deferring QMF build, accountId=" << accountId;
    const QByteArray sigCrlf = toCrlf(sig);
    const bool hasAtt = !attachments.isEmpty();
    QTimer::singleShot(0, this, [this, accountId, subject, to, cc, bcc, signedInner, sigCrlf, micalg, hasAtt]() {
        finishSignedMimeSend(accountId, subject, to, cc, bcc, signedInner, sigCrlf, micalg, hasAtt);
    });
}

void GpgEngine::finishSignedMimeSend(int accountId, const QString &subject,
                                     const QStringList &to, const QStringList &cc,
                                     const QStringList &bcc, const QByteArray &signedInner,
                                     const QByteArray &signature, const QString &micalg,
                                     bool hasAttachments)
{
    const QMailAccountId accId(static_cast<quint64>(accountId));
    QMailAccount account(accId);
    const QString fromAddr = account.fromAddress().toString();
    qWarning() << "[sign] building msg, account" << accountId << "from" << fromAddr;

    const QByteArray boundary = mimeBoundary();
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
    // No User-Agent — see the encrypted send path above.
    rfc += "MIME-Version: 1.0\r\n";
    // micalg mirrors the hash the signing engine ACTUALLY used (from the sign
    // result) — required by RFC 3156 for verifiers that pre-select the digest.
    rfc += "Content-Type: multipart/signed; micalg=\""
         + (micalg.isEmpty() ? QByteArray("pgp-sha256") : micalg.toUtf8()) + "\";\r\n";
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

    std::unique_ptr<GpgME::Context> ctx = makeCtx();
    if (ctx) {
        ctx->setKeyListMode(GpgME::Local | GpgME::WithSecret);
        GpgME::Error kerr;
        const GpgME::Key key = ctx->key(keyid.toUtf8().constData(), kerr, false);
        if (!kerr && !key.isNull()) {
            m[QStringLiteral("inKeyring")] = true;
            m[QStringLiteral("revoked")] = key.isRevoked();
            m[QStringLiteral("expired")] = key.isExpired();
            m[QStringLiteral("hasSecret")] = key.hasSecret();
            const GpgME::Subkey pk = key.subkey(0);
            if (!pk.isNull()) {
                m[QStringLiteral("bits")] = QString::number(pk.length());
                m[QStringLiteral("algo")] = QString::fromUtf8(pk.publicKeyAlgorithmAsString());
                m[QStringLiteral("created")] = keyEpochDate(pk.creationTime());
                m[QStringLiteral("fpr")] = QString::fromUtf8(pk.fingerprint() ? pk.fingerprint() : "");
            }
            QStringList uids;
            for (const GpgME::UserID &u : key.userIDs()) {
                const QString us = QString::fromUtf8(u.id() ? u.id() : "").trimmed();
                if (!us.isEmpty() && !uids.contains(us)) uids.append(us);
            }
            m[QStringLiteral("uids")] = uids;
        }
    }

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

    // A decrypt ATTEMPT with pinentry mode ERROR (never prompts, never uses a
    // passphrase): gpg reports the recipient key ids before it stops, and the
    // decrypt result carries them even when decryption fails (no secret key /
    // key locked). The plaintext, if any, is discarded.
    std::unique_ptr<GpgME::Context> ctx = makeCtx();
    if (!ctx) { result[QStringLiteral("error")] = QStringLiteral("GPGME context unavailable."); return result; }
    ctx->setPinentryMode(GpgME::Context::PinentryError);
    GpgME::Data din(block.constData(), static_cast<size_t>(block.size()), false);
    GpgME::Data dout;
    const std::pair<GpgME::DecryptionResult, GpgME::VerificationResult> res =
        ctx->decryptAndVerify(din, dout);

    QStringList keyIds;
    for (const GpgME::DecryptionResult::Recipient &r : res.first.recipients()) {
        const QString id = QString::fromUtf8(r.keyID() ? r.keyID() : "");
        if (!id.isEmpty() && !keyIds.contains(id)) keyIds.append(id);
    }
    // Signature visibility matches the old packet scan: an unencrypted signed
    // block shows its signature; one INSIDE ciphertext only after decryption.
    bool signedSeen = block.contains("-----BEGIN PGP SIGNED MESSAGE-----");
    if (!res.first.error() && res.second.numSignatures() > 0)
        signedSeen = true;
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

// --- Templates ---------------------------------------------------------------

int GpgEngine::templatesFolderId(int accountId, bool create)
{
    Q_UNUSED(accountId)
    Q_UNUSED(create)
    // Templates now live in the shared LOCAL storage folder (id 1), NOT a per-account
    // child folder. A per-account "Templates" folder got DELETED by "Sync folders":
    // an IMAP folder-list sync reconciles away any local folder the server doesn't
    // know (confirmed on device: create template → Sync folders → folder gone). Not
    // setting SynchronizationEnabled was NOT enough. Folder 1 (the messageserver's
    // local storage / outbox fallback) always exists and is never folder-synced.
    // Templates are tagged (sfmail-template=1) + scoped by parentAccountId so
    // listTemplates can pick them out from transient outgoing mail also in folder 1.
    return 1;
}

int GpgEngine::saveTemplate(int accountId, const QString &subject,
                            const QStringList &to, const QStringList &cc,
                            const QStringList &bcc, const QString &body,
                            const QString &cryptoKind, bool encrypt, bool sign)
{
    const QMailAccountId accId(static_cast<quint64>(accountId));
    if (!accId.isValid()) return 0;
    QMailAccount account(accId);
    const QString fromAddr = account.fromAddress().toString();

    // Build a plain text/plain RFC2822 ourselves and parse via fromRfc2822 — like
    // the send path: incremental QMailMessage content setters can block the GUI
    // thread on this device (see qmf-send-im-app-prozess-blockiert).
    QByteArray rfc;
    rfc += "From: " + fromAddr.toUtf8() + "\r\n";
    if (!to.isEmpty())  rfc += "To: "  + to.join(QStringLiteral(", ")).toUtf8()  + "\r\n";
    if (!cc.isEmpty())  rfc += "Cc: "  + cc.join(QStringLiteral(", ")).toUtf8()  + "\r\n";
    if (!bcc.isEmpty()) rfc += "Bcc: " + bcc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    rfc += "Subject: " + subject.toUtf8() + "\r\n";
    rfc += "Date: " + QMailTimeStamp::currentDateTime().toString().toUtf8() + "\r\n";
    rfc += "MIME-Version: 1.0\r\n";
    rfc += "Content-Type: text/plain; charset=UTF-8\r\n";
    rfc += "Content-Transfer-Encoding: 8bit\r\n";
    rfc += "\r\n";
    rfc += body.toUtf8();

    // Heap-allocate and never delete — same QMF ABI-shim destructor UAF as the send
    // path (see qmf-abi-shim-5-0-build-auf-5-1). Templates are saved rarely.
    QMailMessage *m = new QMailMessage(QMailMessage::fromRfc2822(rfc));
    // LOCAL storage folder (id 1) — never folder-synced, so "Sync folders" can't
    // delete our templates. Built NUMERICALLY (the PredefinedFolderId ctor blocks
    // the GUI thread here). parentAccountId MUST be the real mail account: folder 1
    // is shared local storage and QMailStore REQUIRES a valid parent account
    // (setting it invalid → addMessage ConstraintFailure — the 0.3.97 regression).
    // The template still can't leak into a mailbox view because it carries NO Inbox/
    // Draft/Sent/Trash/Outbox status (POP3 filters those by status).
    m->setParentAccountId(accId);
    m->setParentFolderId(QMailFolderId(static_cast<quint64>(1)));
    // DELIBERATELY only ContentAvailable|Read — NO Draft/Sent/Trash/Outbox/Outgoing
    // status (on POP3 the standard-folder views filter by STATUS).
    m->setStatus(QMailMessage::ContentAvailable, true);
    m->setStatus(QMailMessage::Read, true);
    // Marker so listTemplates can tell templates apart from transient outgoing mail
    // also in folder 1; keep the account field too (belt-and-suspenders scoping).
    m->setCustomField(QStringLiteral("sfmail-template"), QStringLiteral("1"));
    m->setCustomField(QStringLiteral("sfmail-tmpl-account"), QString::number(accountId));
    m->setCustomField(QStringLiteral("sfmail-crypto"), cryptoKind);
    m->setCustomField(QStringLiteral("sfmail-encrypt"), encrypt ? QStringLiteral("1") : QStringLiteral("0"));
    m->setCustomField(QStringLiteral("sfmail-sign"), sign ? QStringLiteral("1") : QStringLiteral("0"));
    const bool ok = QMailStore::instance()->addMessage(m);
    qWarning() << "[tmpl] saveTemplate addMessage ok=" << ok << "acct=" << accountId
               << "storeErr=" << static_cast<int>(QMailStore::instance()->lastError());
    if (!ok)
        return 0;
    return static_cast<int>(m->id().toULongLong());
}

QVariantMap GpgEngine::templateInfo(int messageId)
{
    QVariantMap out;
    const QMailMessageId mid(static_cast<quint64>(messageId));
    if (!mid.isValid()) return out;

    // Subject + crypto choice come from metadata (QMF decodes the subject for us,
    // and custom fields are stored/read reliably). Metadata-only load is safe.
    QMailMessageMetaData meta(mid);
    out[QStringLiteral("subject")] = meta.subject();
    out[QStringLiteral("cryptoKind")] = meta.customField(QStringLiteral("sfmail-crypto"));
    out[QStringLiteral("encrypt")] = (meta.customField(QStringLiteral("sfmail-encrypt")) == QStringLiteral("1"));
    out[QStringLiteral("sign")]    = (meta.customField(QStringLiteral("sfmail-sign")) == QStringLiteral("1"));

    // To/Cc/Bcc + body: read the stored message file directly (loading a full
    // QMailMessage in the plugin can freeze the GUI — qmailmessage-im-plugin-...).
    QStringList to, cc, bcc;
    QString bodyText;
    const QString path = messageFilePath(messageId);
    if (!path.isEmpty()) {
        QFile bf(path);
        if (bf.open(QIODevice::ReadOnly)) {
            const QByteArray all = bf.readAll();
            bf.close();
            int sep = all.indexOf("\r\n\r\n"); int sl = 4;
            if (sep < 0) { sep = all.indexOf("\n\n"); sl = 2; }
            const QByteArray head = sep >= 0 ? all.left(sep) : all;
            QByteArray raw = sep >= 0 ? all.mid(sep + sl) : QByteArray();
            const QString unf = unfoldHeaders(head);
            const QString lower = unf.toLower();
            if (lower.contains(QStringLiteral("quoted-printable")))
                raw = decodeQuotedPrintable(raw);
            else if (lower.contains(QStringLiteral("content-transfer-encoding: base64")))
                raw = QByteArray::fromBase64(raw);
            bodyText = QString::fromUtf8(raw);

            auto splitAddrs = [](const QString &v) {
                QStringList o;
                for (const QString &p : v.split(QLatin1Char(',')))
                    if (!p.trimmed().isEmpty()) o << p.trimmed();
                return o;
            };
            for (const QString &line : unf.split(QLatin1Char('\n'))) {
                const QString low = line.toLower();
                if (low.startsWith(QStringLiteral("to:")))  to  = splitAddrs(line.mid(3));
                else if (low.startsWith(QStringLiteral("cc:")))  cc  = splitAddrs(line.mid(3));
                else if (low.startsWith(QStringLiteral("bcc:"))) bcc = splitAddrs(line.mid(4));
            }
        }
    }
    out[QStringLiteral("to")]  = to;
    out[QStringLiteral("cc")]  = cc;
    out[QStringLiteral("bcc")] = bcc;
    out[QStringLiteral("body")] = bodyText;
    return out;
}

QVariantList GpgEngine::listTemplates(int accountId)
{
    QVariantList out;
    // Templates live in the local storage folder (id 1) — see templatesFolderId().
    const QMailMessageKey key =
        QMailMessageKey::parentFolderId(QMailFolderId(static_cast<quint64>(1)));
    const QMailMessageIdList ids = QMailStore::instance()->queryMessages(key);
    const quint64 acct = static_cast<quint64>(accountId);
    // Newest first (the store hands them back oldest-first).
    for (int i = ids.size() - 1; i >= 0; --i) {
        const QMailMessageId id = ids.at(i);
        QMailMessageMetaData meta(id);   // metadata-only load is safe in the plugin
        // Folder 1 also holds transient outgoing mail — take only our templates,
        // scoped to this account by parentAccountId (matches how saveTemplate stores
        // them). The sfmail-tmpl-account field is a redundant fallback.
        if (meta.customField(QStringLiteral("sfmail-template")) != QStringLiteral("1")) continue;
        if (meta.parentAccountId().toULongLong() != acct) continue;
        QVariantMap m;
        m[QStringLiteral("id")] = static_cast<int>(id.toULongLong());
        m[QStringLiteral("subject")] = meta.subject();
        m[QStringLiteral("cryptoKind")] = meta.customField(QStringLiteral("sfmail-crypto"));
        m[QStringLiteral("encrypt")] =
            (meta.customField(QStringLiteral("sfmail-encrypt")) == QStringLiteral("1"));
        m[QStringLiteral("sign")] =
            (meta.customField(QStringLiteral("sfmail-sign")) == QStringLiteral("1"));
        out << m;
    }
    qWarning() << "[tmpl] listTemplates acct=" << accountId
               << "folder1msgs=" << ids.size() << "templatesFound=" << out.size();
    return out;
}

bool GpgEngine::deleteTemplate(int messageId)
{
    const QMailMessageId mid(static_cast<quint64>(messageId));
    if (!mid.isValid()) return false;
    // Local template — never leave a server removal record.
    return QMailStore::instance()->removeMessage(mid, QMailStore::NoRemovalRecord);
}

int GpgEngine::saveDraft(int accountId, const QString &subject,
                         const QStringList &to, const QStringList &cc,
                         const QStringList &bcc, const QString &body,
                         const QString &cryptoKind, bool encrypt, bool sign)
{
    const QMailAccountId accId(static_cast<quint64>(accountId));
    if (!accId.isValid()) return 0;
    QMailAccount account(accId);
    const QString fromAddr = account.fromAddress().toString();

    // Self-built text/plain RFC2822 parsed via fromRfc2822 — like the send and
    // template paths. Incremental QMailMessage content setters (and the native
    // EmailMessage.saveDraft()) can block/crash the GUI thread on this device
    // (see qmf-send-im-app-prozess-blockiert, qmf-abi-shim-5-0-build-auf-5-1).
    QByteArray rfc;
    rfc += "From: " + fromAddr.toUtf8() + "\r\n";
    if (!to.isEmpty())  rfc += "To: "  + to.join(QStringLiteral(", ")).toUtf8()  + "\r\n";
    if (!cc.isEmpty())  rfc += "Cc: "  + cc.join(QStringLiteral(", ")).toUtf8()  + "\r\n";
    if (!bcc.isEmpty()) rfc += "Bcc: " + bcc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    rfc += "Subject: " + subject.toUtf8() + "\r\n";
    rfc += "Date: " + QMailTimeStamp::currentDateTime().toString().toUtf8() + "\r\n";
    rfc += "MIME-Version: 1.0\r\n";
    rfc += "Content-Type: text/plain; charset=UTF-8\r\n";
    rfc += "Content-Transfer-Encoding: 8bit\r\n";
    rfc += "\r\n";
    rfc += body.toUtf8();

    // Heap-allocate and never delete — same QMF ABI-shim destructor UAF as the
    // send path. Drafts are saved rarely.
    QMailMessage *m = new QMailMessage(QMailMessage::fromRfc2822(rfc));
    m->setParentAccountId(accId);
    // Put it in the account's Drafts folder so it shows in the Drafts view. If the
    // account has none, fall back to the shared local folder (id 1), built
    // NUMERICALLY (the PredefinedFolderId ctor blocks the GUI thread here). The
    // Draft status flag is what the Drafts view filters on for POP3, where all
    // standard-folder mail lives in one physical local folder.
    QMailFolderId drafts = account.standardFolder(QMailFolder::DraftsFolder);
    if (!drafts.isValid()) drafts = QMailFolderId(static_cast<quint64>(1));
    m->setParentFolderId(drafts);
    m->setStatus(QMailMessage::ContentAvailable, true);
    m->setStatus(QMailMessage::Read, true);
    m->setStatus(QMailMessage::Draft, true);
    // Remember the crypto choice so editing the draft restores it (reuses the
    // template custom-field names, read back by templateInfo()).
    m->setCustomField(QStringLiteral("sfmail-crypto"), cryptoKind);
    m->setCustomField(QStringLiteral("sfmail-encrypt"), encrypt ? QStringLiteral("1") : QStringLiteral("0"));
    m->setCustomField(QStringLiteral("sfmail-sign"), sign ? QStringLiteral("1") : QStringLiteral("0"));
    if (!QMailStore::instance()->addMessage(m))
        return 0;
    return static_cast<int>(m->id().toULongLong());
}

bool GpgEngine::deleteDraft(int messageId)
{
    const QMailMessageId mid(static_cast<quint64>(messageId));
    if (!mid.isValid()) return false;
    // Draft was created locally by us — remove without a server removal record.
    return QMailStore::instance()->removeMessage(mid, QMailStore::NoRemovalRecord);
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
