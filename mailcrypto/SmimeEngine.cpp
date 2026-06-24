#include "SmimeEngine.h"

#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QDebug>
#include <QSet>
#include <QUrl>
#include <QEventLoop>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QDateTime>
#include <QTextCodec>
#include <qmailmessage.h>
#include <qmailaccount.h>
#include <qmailfolder.h>
#include <qmailstore.h>
#include <qmailserviceaction.h>
#include <qmailtimestamp.h>
#include <qmailaddress.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Resolve the on-disk RFC822 file of a stored QMF message (id → mailfile via
// qmailstore.db). Does NOT construct a QMailMessage (that can freeze the app).
static QString smimeMessageFilePath(int messageId)
{
    const QString dbPath = QDir::homePath() + QStringLiteral("/.qmf/database/qmailstore.db");
    QString path;
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"),
                                                    QStringLiteral("smime_msg"));
        db.setDatabaseName(dbPath);
        if (db.open()) {
            QSqlQuery q(db);
            q.prepare(QStringLiteral("SELECT mailfile FROM mailmessages WHERE id = ?"));
            q.addBindValue(messageId);
            if (q.exec() && q.next()) {
                QString mf = q.value(0).toString();
                const int c = mf.indexOf(QLatin1Char(':'));   // strip "qmfstoragemanager:"
                if (c > 0 && mf.left(c).contains(QStringLiteral("storagemanager"), Qt::CaseInsensitive))
                    mf = mf.mid(c + 1);
                if (!mf.isEmpty()) {
                    path = mf.startsWith(QLatin1Char('/')) ? mf
                         : (QDir::homePath() + QStringLiteral("/.qmf/mail/") + mf);
                }
            }
            db.close();
        }
    }
    QSqlDatabase::removeDatabase(QStringLiteral("smime_msg"));
    return path;
}

// Read the full raw bytes of a stored message (empty if unavailable).
static QByteArray smimeRawMessage(int messageId)
{
    const QString p = smimeMessageFilePath(messageId);
    if (p.isEmpty()) return QByteArray();
    QFile f(p);
    if (!f.open(QIODevice::ReadOnly)) return QByteArray();
    const QByteArray d = f.readAll();
    f.close();
    return d;
}

// Pull the base64 body of the first MIME part whose Content-Type contains
// `mimeMatch` and decode it to DER. Works for a single-part pkcs7-mime message
// (whole body) and for a pkcs7-signature part inside multipart/signed.
static QByteArray smimePkcs7Der(const QByteArray &raw, const QByteArray &mimeMatch)
{
    int m = raw.indexOf(mimeMatch);
    if (m < 0) return QByteArray();
    int b = raw.indexOf("\r\n\r\n", m); int blen = 4;
    if (b < 0) { b = raw.indexOf("\n\n", m); blen = 2; }
    if (b < 0) return QByteArray();
    QByteArray body;
    const QList<QByteArray> lines = raw.mid(b + blen).split('\n');
    for (QByteArray ln : lines) {
        if (ln.endsWith('\r')) ln.chop(1);
        if (ln.startsWith("--")) break;   // next MIME boundary delimiter
        body += ln;
    }
    return QByteArray::fromBase64(body);
}

// Decode quoted-printable (handles =XX hex escapes and =<CRLF> soft line breaks).
static QByteArray decodeQuotedPrintable(const QByteArray &in)
{
    QByteArray out;
    for (int i = 0; i < in.size(); ++i) {
        const char c = in.at(i);
        if (c == '=' && i + 1 < in.size()) {
            const char n = in.at(i + 1);
            if (n == '\n') { ++i; continue; }                                   // =\n
            if (n == '\r' && i + 2 < in.size() && in.at(i + 2) == '\n') { i += 2; continue; }
            if (i + 2 < in.size()) {
                bool ok = false;
                const int v = in.mid(i + 1, 2).toInt(&ok, 16);
                if (ok) { out.append(char(v)); i += 2; continue; }
            }
        }
        out.append(c);
    }
    return out;
}

// Turn a text/plain part body into a QString, honouring its charset and
// Content-Transfer-Encoding. Outlook commonly sends iso-8859-1/windows-1252 with
// 8bit or quoted-printable; decoding those as UTF-8 turns umlauts into U+FFFD.
static QString decodeTextBody(const QByteArray &body, QByteArray charset, QByteArray cte)
{
    charset = charset.toLower().trimmed();
    cte = cte.toLower().trimmed();
    QByteArray bytes = body;
    if (cte.contains("quoted-printable")) bytes = decodeQuotedPrintable(bytes);
    else if (cte.contains("base64"))      bytes = QByteArray::fromBase64(bytes);
    if (charset.isEmpty()) charset = "utf-8";
    if (QTextCodec *codec = QTextCodec::codecForName(charset))
        return codec->toUnicode(bytes);
    if (charset.startsWith("iso-8859") || charset.startsWith("windows-125") || charset.contains("latin"))
        return QString::fromLatin1(bytes);
    return QString::fromUtf8(bytes);
}

// Readable text from a decrypted inner MIME entity: the first text/plain part,
// decoded per its charset + Content-Transfer-Encoding.
static QString smimeReadableText(const QByteArray &mimeIn)
{
    // Defense-in-depth size cap: only ever look at a bounded prefix of the
    // decrypted content (it is already bounded by the message size, but this keeps
    // a pathological message from being copied/decoded without limit).
    static const int kSmimeMaxBytes = 16 * 1024 * 1024;   // 16 MB of readable text
    const QByteArray mime = mimeIn.size() > kSmimeMaxBytes ? mimeIn.left(kSmimeMaxBytes) : mimeIn;
    int t = mime.indexOf("text/plain");
    if (t < 0) return QString::fromUtf8(mime).trimmed();
    // The part's header block runs from the start of the Content-Type line to the
    // empty line that separates headers from body.
    int hs = mime.lastIndexOf('\n', t); hs = (hs < 0) ? 0 : hs + 1;
    int b = mime.indexOf("\r\n\r\n", t); int blen = 4;
    if (b < 0) { b = mime.indexOf("\n\n", t); blen = 2; }
    if (b < 0) return QString::fromUtf8(mime).trimmed();
    const QByteArray hdr = mime.mid(hs, b - hs);
    const QByteArray hdrLow = hdr.toLower();

    QByteArray charset;
    int ci = hdrLow.indexOf("charset");
    if (ci >= 0) {
        int eq = hdrLow.indexOf('=', ci);
        if (eq >= 0) {
            QByteArray cs = hdr.mid(eq + 1).trimmed();
            cs.replace("\"", "").replace("'", "");
            int end = 0;
            while (end < cs.size() && (isalnum((unsigned char)cs.at(end)) || cs.at(end) == '-' || cs.at(end) == '_')) ++end;
            charset = cs.left(end);
        }
    }
    QByteArray cte;
    int ti = hdrLow.indexOf("content-transfer-encoding");
    if (ti >= 0) { int eq = hdrLow.indexOf(':', ti); if (eq >= 0) cte = hdrLow.mid(eq + 1, 24).trimmed(); }

    QByteArray body;
    for (QByteArray ln : mime.mid(b + blen).split('\n')) {
        if (ln.endsWith('\r')) ln.chop(1);
        if (ln.startsWith("--")) break;   // boundary → end of this part
        body += ln + "\n";
    }
    return decodeTextBody(body, charset, cte).trimmed();
}

// --- S/MIME attachment extraction (mirrors the PGP walkMime; kept separate so the
//     proven PGP path stays untouched) ----------------------------------------
static QString smimeSafeName(const QString &name, int idx, const QString &mimeType)
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

// One (unfolded) header field value from a MIME header block.
static QString smimeHeaderField(const QByteArray &header, const char *name)
{
    QByteArray padded = QByteArray("\n") + header;
    padded.replace("\r\n ", " ").replace("\r\n\t", " ").replace("\n ", " ").replace("\n\t", " ");
    const QByteArray hl = padded.toLower();
    const QByteArray key = QByteArray("\n") + QByteArray(name).toLower() + ":";
    const int i = hl.indexOf(key);
    if (i < 0) return QString();
    const int start = i + key.size();
    int end = padded.indexOf('\n', start);
    if (end < 0) end = padded.size();
    return QString::fromUtf8(padded.mid(start, end - start)).trimmed();
}

// A ;-delimited parameter (e.g. filename / name / boundary) from a header value.
static QString smimeParam(const QString &full, const QString &key)
{
    const int i = full.toLower().indexOf(key.toLower());
    if (i < 0) return QString();
    const int eq = full.indexOf('=', i);
    if (eq < 0) return QString();
    QString v = full.mid(eq + 1).trimmed();
    if (v.startsWith('"')) { v = v.mid(1); const int q = v.indexOf('"'); if (q >= 0) v = v.left(q); }
    else v = v.section(';', 0, 0).trimmed();
    return v;
}

// partsDir/loc: on SFOS 4.6 QMF stores each MIME part as a SEPARATE file
// "<base>-parts/<location>" (e.g. 1.2) and the main mailfile only holds the small
// inline parts. So when a leaf's inline body is missing/short we read the real body
// from "<partsDir>/<loc>". loc tracks the 1-based dotted QMF part path. partsDir
// empty (e.g. decrypted in-memory content) → inline only.
static void smimeWalkAtts(const QByteArray &mime, int depth, const QString &cacheDir,
                          QVariantList *out, const QString &partsDir, const QString &loc)
{
    if (depth > 12 || out->size() >= 256) return;
    int sep = mime.indexOf("\r\n\r\n"); int sl = 4;
    if (sep < 0) { sep = mime.indexOf("\n\n"); sl = 2; }
    const QByteArray header = sep >= 0 ? mime.left(sep) : mime;
    const QByteArray body   = sep >= 0 ? mime.mid(sep + sl) : QByteArray();

    const QString ctypeFull = smimeHeaderField(header, "content-type");
    const QString ctype = ctypeFull.section(';', 0, 0).trimmed().toLower();
    const QString cte   = smimeHeaderField(header, "content-transfer-encoding").toLower();
    const QString cdisp = smimeHeaderField(header, "content-disposition").toLower();

    if (ctype.startsWith(QStringLiteral("multipart/"))) {
        const QString bnd = smimeParam(ctypeFull, QStringLiteral("boundary"));
        if (bnd.isEmpty()) return;
        const QByteArray delim = "--" + bnd.toUtf8();
        QList<QByteArray> chunks; QByteArray cur; bool started = false;
        for (const QByteArray &lineRaw : body.split('\n')) {
            QByteArray line = lineRaw; if (line.endsWith('\r')) line.chop(1);
            if (line.startsWith(delim)) {
                if (started && !cur.isEmpty()) chunks.append(cur);
                cur.clear(); started = true;
                if (line == delim + "--") break;
                continue;
            }
            if (started) { cur.append(lineRaw); cur.append('\n'); }
        }
        int ci = 0;
        for (const QByteArray &ch : chunks) {
            ++ci;
            const QString childLoc = loc.isEmpty() ? QString::number(ci)
                                                   : (loc + QStringLiteral(".") + QString::number(ci));
            smimeWalkAtts(ch, depth + 1, cacheDir, out, partsDir, childLoc);
        }
        return;
    }

    // Leaf — only collect actual attachments (text bodies are handled elsewhere).
    QString filename = smimeParam(smimeHeaderField(header, "content-disposition"), QStringLiteral("filename"));
    if (filename.isEmpty()) filename = smimeParam(ctypeFull, QStringLiteral("name"));
    const bool isAtt = cdisp.contains(QStringLiteral("attachment")) || !filename.isEmpty();
    if (!isAtt) return;
    // Never list S/MIME plumbing (the detached signature / the CMS wrapper) as a
    // user attachment — QMF's native model hides these too.
    if (ctype.contains(QStringLiteral("pkcs7-signature")) || ctype.contains(QStringLiteral("pkcs7-mime"))
        || ctype.contains(QStringLiteral("x-pkcs7"))
        || filename.toLower() == QStringLiteral("smime.p7s")
        || filename.toLower() == QStringLiteral("smime.p7m")) return;
    QByteArray decoded;
    // SFOS 4.6: prefer the external part file (QMF stores it already decoded).
    if (!partsDir.isEmpty() && !loc.isEmpty()) {
        const QString pf = partsDir + QStringLiteral("/") + loc;
        if (QFileInfo::exists(pf)) {
            QFile f(pf);
            if (f.open(QIODevice::ReadOnly)) { decoded = f.readAll(); f.close(); }
        }
    }
    if (decoded.isEmpty()) {                  // fall back to the inline body
        if (body.size() > 256LL * 1024 * 1024) return;   // per-part cap
        decoded = body;
        if (cte.contains(QStringLiteral("quoted-printable"))) {
            decoded = decodeQuotedPrintable(body);
        } else if (cte.contains(QStringLiteral("base64"))) {
            QByteArray b64; b64.reserve(body.size());
            for (char c : body) if (c != '\n' && c != '\r') b64.append(c);
            decoded = QByteArray::fromBase64(b64);
        }
    }
    if (decoded.isEmpty()) return;            // nothing to show

    const int idx = out->size();
    const QString mt = ctype.isEmpty() ? QStringLiteral("application/octet-stream") : ctype;
    const QString name = smimeSafeName(filename, idx, mt);
    const QString outPath = cacheDir + QStringLiteral("/") + name;
    QFile f(outPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    f.write(decoded);
    f.close();
    QVariantMap m;
    m[QStringLiteral("name")] = name;
    m[QStringLiteral("mimeType")] = mt;
    m[QStringLiteral("path")] = outPath;
    m[QStringLiteral("url")] = QUrl::fromLocalFile(outPath).toString();
    m[QStringLiteral("isImage")] = mt.startsWith(QStringLiteral("image/"));
    m[QStringLiteral("size")] = decoded.size();
    out->append(m);
}

static QVariantList smimeExtractAttachments(const QByteArray &content, const QString &partsDir);  // fwd

QVariantList SmimeEngine::takeLastAttachments()
{
    const QVariantList a = m_lastDecAttachments;
    m_lastDecAttachments.clear();
    return a;
}

QVariantList SmimeEngine::plainAttachments(int messageId)
{
    const QByteArray raw = smimeRawMessage(messageId);   // mailfile (small inline parts)
    if (raw.isEmpty()) return QVariantList();
    // On 4.6 large parts live next to the mailfile in "<base>-parts/<loc>".
    const QString base = smimeMessageFilePath(messageId);
    const QString partsDir = base.isEmpty() ? QString() : (base + QStringLiteral("-parts"));
    return smimeExtractAttachments(raw, partsDir);
}

// Extract attachments of a MIME entity into a fresh private cache. partsDir (4.6)
// supplies external part files; empty for in-memory (decrypted) content.
static QVariantList smimeExtractAttachments(const QByteArray &content, const QString &partsDir)
{
    const QString cacheDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                             + QStringLiteral("/smime-decrypted");
    QDir cd(cacheDir);
    if (cd.exists())
        for (const QString &old : cd.entryList(QDir::Files)) cd.remove(old);
    QDir().mkpath(cacheDir);
    QVariantList out;
    smimeWalkAtts(content, 0, cacheDir, &out, partsDir, QString());
    return out;
}

// Extract every PEM block of the given type ("CERTIFICATE", "PRIVATE KEY", …)
// from a buffer. Returns each block including its BEGIN/END lines.
static QList<QByteArray> pemBlocks(const QByteArray &buf, const QByteArray &kind)
{
    QList<QByteArray> out;
    const QByteArray begin = "-----BEGIN " + kind + "-----";
    const QByteArray end   = "-----END " + kind + "-----";
    int pos = 0;
    while (true) {
        int b = buf.indexOf(begin, pos);
        if (b < 0) break;
        int e = buf.indexOf(end, b);
        if (e < 0) break;
        e += end.size();
        out.append(buf.mid(b, e - b) + "\n");
        pos = e;
    }
    return out;
}

// Any private-key PEM flavour OpenSSL emits with -nodes.
static QList<QByteArray> allPrivateKeys(const QByteArray &buf)
{
    QList<QByteArray> keys;
    keys += pemBlocks(buf, "PRIVATE KEY");
    keys += pemBlocks(buf, "RSA PRIVATE KEY");
    keys += pemBlocks(buf, "EC PRIVATE KEY");
    return keys;
}

static QByteArray toCrlf(const QByteArray &in)
{
    QByteArray b = in; b.replace("\r\n", "\n"); b.replace('\n', "\r\n"); return b;
}

// The inner MIME entity (body + attachments) that gets signed/encrypted as a whole.
static QByteArray buildInnerMime(const QString &bodyText, const QVariantList &attachments, qint64 stamp)
{
    const QByteArray CRLF = "\r\n";
    if (attachments.isEmpty()) {
        QByteArray m;
        m += "Content-Type: text/plain; charset=utf-8" + CRLF;
        m += "Content-Transfer-Encoding: 8bit" + CRLF + CRLF;
        m += toCrlf(bodyText.toUtf8());
        if (!m.endsWith(CRLF)) m += CRLF;
        return m;
    }
    const QByteArray bnd = "sfmail-inner-" + QByteArray::number(stamp);
    QByteArray m;
    m += "Content-Type: multipart/mixed; boundary=\"" + bnd + "\"" + CRLF;
    m += "MIME-Version: 1.0" + CRLF + CRLF;
    m += "--" + bnd + CRLF;
    m += "Content-Type: text/plain; charset=utf-8" + CRLF;
    m += "Content-Transfer-Encoding: 8bit" + CRLF + CRLF;
    m += toCrlf(bodyText.toUtf8());
    if (!m.endsWith(CRLF)) m += CRLF;
    for (const QVariant &v : attachments) {
        const QVariantMap a = v.toMap();
        QString path = a.value(QStringLiteral("path")).toString();
        if (path.isEmpty()) path = a.value(QStringLiteral("url")).toString();
        if (path.startsWith(QStringLiteral("file://"))) path = path.mid(7);
        QFile af(path);
        if (!af.open(QIODevice::ReadOnly)) continue;
        const QByteArray data = af.readAll(); af.close();
        QByteArray name = a.value(QStringLiteral("name")).toString().toUtf8();
        if (name.isEmpty()) name = QFileInfo(path).fileName().toUtf8();
        QByteArray mime = a.value(QStringLiteral("mimeType")).toString().toUtf8();
        if (mime.isEmpty()) mime = "application/octet-stream";
        m += "--" + bnd + CRLF;
        m += "Content-Type: " + mime + "; name=\"" + name + "\"" + CRLF;
        m += "Content-Transfer-Encoding: base64" + CRLF;
        m += "Content-Disposition: attachment; filename=\"" + name + "\"" + CRLF + CRLF;
        const QByteArray b64 = data.toBase64();
        for (int i = 0; i < b64.size(); i += 76) { m += b64.mid(i, 76); m += CRLF; }
    }
    m += "--" + bnd + "--" + CRLF;
    return m;
}

// Wrap a DER CMS blob as a base64 application/pkcs7-mime MIME entity.
static QByteArray pkcs7MimeEntity(const QByteArray &der, const QByteArray &smimeType)
{
    QByteArray m;
    m += "Content-Type: application/pkcs7-mime; smime-type=" + smimeType + "; name=\"smime.p7m\"\r\n";
    m += "Content-Transfer-Encoding: base64\r\n";
    m += "Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\r\n";
    const QByteArray b64 = der.toBase64();
    for (int i = 0; i < b64.size(); i += 76) { m += b64.mid(i, 76); m += "\r\n"; }
    return m;
}

// ---------------------------------------------------------------------------

SmimeEngine::SmimeEngine(QObject *parent) : QObject(parent)
{
    // The sandbox (firejail) HIDES another app's /usr/share/<app>, so we cannot
    // reach harbour-sfmail's /usr/share/harbour-sfmail/gpg from this separate test
    // app. The RPM therefore bundles its OWN copy of the gpgsm stack under our own
    // prefix (same trick harbour-sfmail uses for its gpg). Later, once S/MIME is
    // integrated INTO harbour-sfmail (same process), it reuses that app's stack.
    m_stack   = QStringLiteral("/usr/share/harbour-sfmail/gpg");
    m_gpgsm   = m_stack + QStringLiteral("/bin/gpgsm");
    m_agent   = m_stack + QStringLiteral("/bin/gpg-agent");
    m_dirmngr = m_stack + QStringLiteral("/bin/dirmngr");
    m_lib     = m_stack + QStringLiteral("/lib");
    // The sandbox blocks the SYSTEM /usr/bin/openssl (firejail private-bin), so we
    // bundle openssl too (+ its legacy provider, needed to read Windows/Volksver-
    // schlüsselung .p12 with OpenSSL 3.x). It still uses the SYSTEM libssl/libcrypto.
    m_openssl = m_stack + QStringLiteral("/bin/openssl");

    // Our OWN gpgsm home (keeps harbour-sfmail's OpenPGP keyring untouched).
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    m_home = base + QStringLiteral("/smime");
    QDir().mkpath(m_home);
    QFile::setPermissions(m_home, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);

    // CRITICAL for p12 import: gpgsm hands the private key to gpg-agent, which
    // protects it with a passphrase via "pinentry". In batch/loopback mode the
    // agent only accepts that passphrase when allow-loopback-pinentry is set —
    // without it the key is silently NOT stored (certs import, but 0 secret keys).
    // Also harden the agent cache (see GpgEngine): never keep an unlocked key in
    // agent memory beyond a single operation, shrinking the in-RAM exposure window.
    const QString agentConf = m_home + QStringLiteral("/gpg-agent.conf");
    {
        QFile f(agentConf);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            f.write("allow-loopback-pinentry\n"
                    "default-cache-ttl 0\n"
                    "max-cache-ttl 0\n"
                    "ignore-cache-for-signing\n");
            f.close();
        }
    }

    // S/MIME needs BOTH the bundled gpgsm AND a runnable bundled openssl. On
    // armv7 openssl is not bundled → openssl version is empty → S/MIME is
    // reported unavailable, so the UI hides the S/MIME toggle/menus there.
    m_available = QFileInfo::exists(m_gpgsm);
    if (m_available) {
        QByteArray vo, ve;
        runOpenssl(QStringList() << QStringLiteral("version"), QByteArray(), &vo, &ve, 8000);
        const QString v = QString::fromUtf8(vo).trimmed();
        if (v.isEmpty()) {
            m_available = false;
            qWarning() << "[smime] bundled openssl not runnable — S/MIME unavailable";
        } else {
            m_legacy = v.contains(QStringLiteral("OpenSSL 3")) ? 1 : 0;
            qWarning() << "[smime] ready; gpgsm=" << m_gpgsm << "openssl=" << v
                       << "legacy=" << (m_legacy ? "yes" : "no") << "home=" << m_home;
        }
    }
    if (!m_available && !QFileInfo::exists(m_gpgsm))
        qWarning() << "[smime] gpgsm not found at" << m_gpgsm;
}

void SmimeEngine::log(const QString &s)
{
    qWarning() << "[smime]" << s;
    emit logLine(s);
}

bool SmimeEngine::runGpgsm(const QStringList &args, const QByteArray &stdinData,
                           QByteArray *out, QByteArray *err, int timeoutMs)
{
    QStringList full;
    full << QStringLiteral("--homedir") << m_home
         << QStringLiteral("--batch")
         << QStringLiteral("--disable-crl-checks")
         << QStringLiteral("--agent-program") << m_agent
         << QStringLiteral("--dirmngr-program") << m_dirmngr
         << args;

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    QString ld = m_lib;
    if (env.contains(QStringLiteral("LD_LIBRARY_PATH")))
        ld += QStringLiteral(":") + env.value(QStringLiteral("LD_LIBRARY_PATH"));
    env.insert(QStringLiteral("LD_LIBRARY_PATH"), ld);
    env.insert(QStringLiteral("GNUPGHOME"), m_home);

    QProcess p;
    p.setProcessEnvironment(env);
    p.start(m_gpgsm, full);
    if (!p.waitForStarted(8000)) { if (err) *err = "gpgsm did not start"; return false; }
    if (!stdinData.isEmpty()) p.write(stdinData);
    p.closeWriteChannel();
    if (!p.waitForFinished(timeoutMs)) { p.kill(); if (err) *err = "gpgsm timed out"; return false; }
    if (out) *out = p.readAllStandardOutput();
    if (err) *err = p.readAllStandardError();
    return p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0;
}

bool SmimeEngine::runOpenssl(const QStringList &args, const QByteArray &stdinData,
                             QByteArray *out, QByteArray *err, int timeoutMs)
{
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    // Our bundled openssl finds its legacy provider here (still links the SYSTEM
    // libssl/libcrypto). Do NOT add our gpg lib dir — openssl must use system libs.
    env.insert(QStringLiteral("OPENSSL_MODULES"), m_stack + QStringLiteral("/lib/ossl-modules"));
    QProcess p;
    p.setProcessEnvironment(env);
    p.start(m_openssl, args);
    if (!p.waitForStarted(8000)) { if (err) *err = "openssl did not start"; return false; }
    if (!stdinData.isEmpty()) p.write(stdinData);
    p.closeWriteChannel();
    if (!p.waitForFinished(timeoutMs)) { p.kill(); if (err) *err = "openssl timed out"; return false; }
    if (out) *out = p.readAllStandardOutput();
    if (err) *err = p.readAllStandardError();
    return p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0;
}

bool SmimeEngine::opensslHasLegacy()
{
    if (m_legacy >= 0) return m_legacy == 1;
    QByteArray out, err;
    runOpenssl(QStringList() << QStringLiteral("version"), QByteArray(), &out, &err, 8000);
    // "OpenSSL 3.x" understands -legacy for pkcs12; 1.1.x does not (and doesn't
    // need it — it reads legacy PKCS#12 natively).
    m_legacy = QString::fromUtf8(out).contains(QStringLiteral("OpenSSL 3")) ? 1 : 0;
    log(QStringLiteral("openssl: %1 (legacy flag: %2)")
        .arg(QString::fromUtf8(out).trimmed()).arg(m_legacy ? "yes" : "no"));
    return m_legacy == 1;
}

// ---------------------------------------------------------------------------
// Automatic trust-chain completion via the certificate's own AIA data
// ---------------------------------------------------------------------------

QByteArray SmimeEngine::httpGet(const QString &url, int timeoutMs)
{
    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    QNetworkRequest req((QUrl(url)));
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    QNetworkReply *rep = m_nam->get(req);
    QEventLoop loop;
    QTimer t; t.setSingleShot(true);
    connect(&t, &QTimer::timeout, &loop, &QEventLoop::quit);
    connect(rep, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    t.start(timeoutMs);
    loop.exec();
    QByteArray data;
    if (rep->isFinished() && rep->error() == QNetworkReply::NoError)
        data = rep->readAll();
    rep->deleteLater();
    return data;
}

QString SmimeEngine::aiaCaIssuers(const QString &fingerprint)
{
    // Export the stored cert, then read its Authority Information Access extension.
    // The "CA Issuers" URL points at the ISSUER's certificate — this is how a cert
    // tells us where to obtain the CA above it. We never hard-code any source.
    QByteArray pem, e;
    runGpgsm(QStringList() << QStringLiteral("--armor") << QStringLiteral("--export") << fingerprint,
             QByteArray(), &pem, &e);
    if (pem.isEmpty()) return QString();
    QByteArray out, err;
    runOpenssl(QStringList() << QStringLiteral("x509") << QStringLiteral("-noout")
                             << QStringLiteral("-ext") << QStringLiteral("authorityInfoAccess"),
               pem, &out, &err, 15000);
    for (const QByteArray &lr : out.split('\n')) {
        const QString ln = QString::fromUtf8(lr);
        if (!ln.contains(QStringLiteral("CA Issuers"), Qt::CaseInsensitive)) continue;
        int u = ln.indexOf(QStringLiteral("URI:"));
        if (u >= 0) return ln.mid(u + 4).trimmed();
    }
    return QString();
}

void SmimeEngine::completeChainViaAia()
{
    int fetched = 0;
    for (int guard = 0; guard < 12; ++guard) {
        const QVariantList certs = listCerts();
        QSet<QString> have;
        for (const QVariant &v : certs) have.insert(v.toMap().value(QStringLiteral("fpr")).toString());

        QString url, viaFpr;
        for (const QVariant &v : certs) {
            const QVariantMap m = v.toMap();
            if (m.value(QStringLiteral("isRoot")).toBool()) continue;
            const QString issuer = m.value(QStringLiteral("chainId")).toString();
            if (issuer.isEmpty() || have.contains(issuer)) continue;   // issuer already present
            const QString u = aiaCaIssuers(m.value(QStringLiteral("fpr")).toString());
            if (!u.isEmpty()) { url = u; viaFpr = m.value(QStringLiteral("fpr")).toString(); break; }
        }
        if (url.isEmpty()) break;   // chain complete (or no AIA pointer to follow)

        log(QStringLiteral("AIA: fetching issuer certificate…"));
        const QByteArray certData = httpGet(url, 20000);
        if (certData.isEmpty()) { log(QStringLiteral("AIA: download failed")); break; }
        QByteArray io, ie;
        if (!runGpgsm(QStringList() << QStringLiteral("--import"), certData, &io, &ie)) {
            log(QStringLiteral("AIA: import of fetched issuer failed")); break;
        }
        ++fetched;
    }
    if (fetched) log(QStringLiteral("AIA: %1 issuer cert(s) added").arg(fetched));
}

void SmimeEngine::updateTrustlist()
{
    // trustlist.txt holds the self-signed ROOTs we trust as anchors. Rewrite it
    // from the roots currently in the store (deduplicated). "S relax" = trusted
    // S/MIME root, lenient extension checks.
    const QVariantList certs = listCerts();
    QFile tl(m_home + QStringLiteral("/trustlist.txt"));
    if (!tl.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QSet<QString> done;
    int n = 0;
    for (const QVariant &v : certs) {
        const QVariantMap m = v.toMap();
        if (!m.value(QStringLiteral("isRoot")).toBool()) continue;
        const QString fpr = m.value(QStringLiteral("fpr")).toString();
        if (fpr.isEmpty() || done.contains(fpr)) continue;
        done.insert(fpr);
        tl.write(fpr.toUtf8() + " S relax\n");
        ++n;
    }
    tl.close();
    log(QStringLiteral("trustlist: %1 root(s) trusted").arg(n));
}

// ---------------------------------------------------------------------------
// Certificate import (Stufe 1, milestone 1)
// ---------------------------------------------------------------------------

void SmimeEngine::generateCert(const QString &name, const QString &email,
                               const QString &passphrase, int days)
{
    if (!m_available) { emit importFinished(false, 0, QStringLiteral("S/MIME (openssl) not available")); return; }
    const QString mail = email.trimmed();
    if (mail.isEmpty()) { emit importFinished(false, 0, QStringLiteral("an e-mail address is required")); return; }
    if (days <= 0) days = 730;

    QTemporaryDir tmp(m_home + QStringLiteral("/gen-XXXXXX"));
    if (!tmp.isValid()) { emit importFinished(false, 0, QStringLiteral("cannot create temp dir")); return; }
    const QString wd = tmp.path();
    const QString keyFile  = wd + QStringLiteral("/key.pem");
    const QString certFile = wd + QStringLiteral("/cert.pem");
    const QString p12File  = wd + QStringLiteral("/new.p12");

    // Escape the chars openssl's -subj treats specially.
    auto esc = [](const QString &s) -> QString {
        QString o = s;
        o.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
        o.replace(QStringLiteral("/"),  QStringLiteral("\\/"));
        o.replace(QStringLiteral("="),  QStringLiteral("\\="));
        o.replace(QStringLiteral("+"),  QStringLiteral("\\+"));
        return o;
    };
    const QString cn = name.trimmed().isEmpty() ? mail : name.trimmed();
    const QString subj = QStringLiteral("/CN=") + esc(cn)
                       + QStringLiteral("/emailAddress=") + esc(mail);

    log(QStringLiteral("generating RSA-4096 self-signed S/MIME cert for %1").arg(mail));

    // RSA-4096 self-signed cert with the MANDATORY e-mail attributes. keyUsage +
    // basicConstraints critical; EKU emailProtection; the address in subjectAltName.
    QStringList req;
    req << QStringLiteral("req") << QStringLiteral("-x509")
        << QStringLiteral("-newkey") << QStringLiteral("rsa:4096")
        << QStringLiteral("-keyout") << keyFile
        << QStringLiteral("-out")    << certFile
        << QStringLiteral("-days")   << QString::number(days)
        << QStringLiteral("-nodes")          // key unencrypted in PEM; the p12 protects it
        << QStringLiteral("-sha256")
        << QStringLiteral("-subj")   << subj
        << QStringLiteral("-addext") << QStringLiteral("basicConstraints=critical,CA:FALSE")
        << QStringLiteral("-addext") << QStringLiteral("keyUsage=critical,digitalSignature,keyEncipherment")
        << QStringLiteral("-addext") << QStringLiteral("extendedKeyUsage=emailProtection")
        << QStringLiteral("-addext") << (QStringLiteral("subjectAltName=email:") + mail);
    QByteArray ro, re;
    if (!runOpenssl(req, QByteArray(), &ro, &re, 180000)) {
        emit importFinished(false, 0, QStringLiteral("openssl could not create the key/cert: %1")
                            .arg(QString::fromUtf8(re).trimmed()));
        return;
    }

    // Pack key+cert into a p12 protected by the user's passphrase, then reuse the
    // proven importP12() path (repack → gpgsm import → trust the self-signed root).
    QStringList exp;
    exp << QStringLiteral("pkcs12") << QStringLiteral("-export")
        << QStringLiteral("-inkey") << keyFile
        << QStringLiteral("-in")    << certFile
        << QStringLiteral("-passout") << (QStringLiteral("pass:") + passphrase)
        << QStringLiteral("-out")   << p12File;
    QByteArray eo, ee;
    if (!runOpenssl(exp, QByteArray(), &eo, &ee, 60000)) {
        emit importFinished(false, 0, QStringLiteral("openssl could not package the certificate: %1")
                            .arg(QString::fromUtf8(ee).trimmed()));
        return;
    }

    importP12(p12File, passphrase, QString());   // emits importFinished + certsChanged
}

void SmimeEngine::importP12(const QString &p12Path, const QString &passphrase,
                            const QString &chainPemPath)
{
    if (!m_available) { emit importFinished(false, 0, QStringLiteral("gpgsm not available")); return; }

    QString path = p12Path;
    if (path.startsWith(QStringLiteral("file://"))) path = path.mid(7);
    if (!QFileInfo::exists(path)) { emit importFinished(false, 0, QStringLiteral("file not found: %1").arg(path)); return; }

    QTemporaryDir tmp(m_home + QStringLiteral("/import-XXXXXX"));
    if (!tmp.isValid()) { emit importFinished(false, 0, QStringLiteral("cannot create temp dir")); return; }
    const QString wd = tmp.path();
    const bool legacy = opensslHasLegacy();

    // 1) Dump EVERYTHING (all certs + all private keys, unencrypted) from the .p12.
    //    Volksverschlüsselung/Windows .p12 uses legacy algorithms → -legacy on
    //    OpenSSL 3.x; without it on 1.1.x.
    const QString allPem = wd + QStringLiteral("/all.pem");
    QStringList dump;
    dump << QStringLiteral("pkcs12") << QStringLiteral("-in") << path
         << QStringLiteral("-nodes")
         << QStringLiteral("-passin") << (QStringLiteral("pass:") + passphrase)
         << QStringLiteral("-out") << allPem;
    if (legacy) dump << QStringLiteral("-legacy");
    QByteArray oout, oerr;
    if (!runOpenssl(dump, QByteArray(), &oout, &oerr)) {
        // Retry once with the opposite -legacy choice (covers version surprises).
        QStringList dump2 = dump;
        if (legacy) dump2.removeAll(QStringLiteral("-legacy")); else dump2 << QStringLiteral("-legacy");
        if (!runOpenssl(dump2, QByteArray(), &oout, &oerr)) {
            emit importFinished(false, 0, QStringLiteral("openssl could not read the .p12: %1")
                                .arg(QString::fromUtf8(oerr).trimmed()));
            return;
        }
    }
    QFile af(allPem);
    if (!af.open(QIODevice::ReadOnly)) { emit importFinished(false, 0, QStringLiteral("cannot read dump")); return; }
    const QByteArray all = af.readAll();
    af.close();

    const QList<QByteArray> certs = pemBlocks(all, "CERTIFICATE");
    const QList<QByteArray> keys  = allPrivateKeys(all);
    log(QStringLiteral("p12 dump: %1 certificate(s), %2 private key(s)").arg(certs.size()).arg(keys.size()));
    if (keys.isEmpty() || certs.isEmpty()) {
        emit importFinished(false, 0, QStringLiteral("no keys/certs found in the .p12"));
        return;
    }

    // Helper: modulus of a PEM (cert via x509, key via rsa). Empty on failure.
    auto modOf = [&](const QByteArray &pem, bool isCert) -> QByteArray {
        QStringList a;
        a << (isCert ? QStringLiteral("x509") : QStringLiteral("rsa"))
          << QStringLiteral("-noout") << QStringLiteral("-modulus");
        QByteArray o, e;
        runOpenssl(a, pem, &o, &e, 15000);
        return o.trimmed();   // "Modulus=ABCD..."
    };

    // Pre-compute cert moduli.
    QList<QByteArray> certMod;
    for (const QByteArray &c : certs) certMod.append(modOf(c, true));

    // 2) Which certs are leaves (have a matching private key) vs chain (CA).
    QList<int> leafForKey;            // key index -> cert index (-1 none)
    QVector<bool> isLeaf(certs.size(), false);
    for (const QByteArray &k : keys) {
        const QByteArray km = modOf(k, false);
        int match = -1;
        for (int ci = 0; ci < certs.size(); ++ci)
            if (!km.isEmpty() && km == certMod[ci]) { match = ci; break; }
        leafForKey.append(match);
        if (match >= 0) isLeaf[match] = true;
    }

    // Chain PEM: an explicit file if given, else all non-leaf certs from the .p12.
    QByteArray chainPem;
    if (!chainPemPath.isEmpty()) {
        QString cp = chainPemPath; if (cp.startsWith(QStringLiteral("file://"))) cp = cp.mid(7);
        QFile cf(cp); if (cf.open(QIODevice::ReadOnly)) { chainPem = cf.readAll(); cf.close(); }
    }
    if (chainPem.isEmpty())
        for (int ci = 0; ci < certs.size(); ++ci) if (!isLeaf[ci]) chainPem += certs[ci];
    const QString chainFile = wd + QStringLiteral("/chain.pem");
    { QFile f(chainFile); if (f.open(QIODevice::WriteOnly)) { f.write(chainPem); f.close(); } }

    // 3) For each private key: build a clean single-key p12 and import it. gpgsm
    //    -export keeps only one key, so one p12 per key is mandatory. Protect the
    //    repacked p12 with the USER's OWN passphrase — gpgsm reuses it as the
    //    stored key's protection passphrase, so the user later decrypts with the
    //    SAME passphrase they already know (not a throwaway one).
    int imported = 0;
    for (int ki = 0; ki < keys.size(); ++ki) {
        const int ci = leafForKey[ki];
        if (ci < 0) { log(QStringLiteral("key %1: no matching cert, skipped").arg(ki)); continue; }
        const QString keyFile  = wd + QStringLiteral("/key%1.pem").arg(ki);
        const QString certFile = wd + QStringLiteral("/cert%1.pem").arg(ki);
        const QString p12File  = wd + QStringLiteral("/key%1.p12").arg(ki);
        { QFile f(keyFile);  if (f.open(QIODevice::WriteOnly)) { f.write(keys[ki]);  f.close(); } }
        { QFile f(certFile); if (f.open(QIODevice::WriteOnly)) { f.write(certs[ci]); f.close(); } }

        QStringList exp;
        exp << QStringLiteral("pkcs12") << QStringLiteral("-export")
            << QStringLiteral("-inkey") << keyFile
            << QStringLiteral("-in") << certFile;
        if (!chainPem.isEmpty()) exp << QStringLiteral("-certfile") << chainFile;
        exp << QStringLiteral("-passout") << (QStringLiteral("pass:") + passphrase)
            << QStringLiteral("-out") << p12File;
        QByteArray eo, ee;
        if (!runOpenssl(exp, QByteArray(), &eo, &ee)) {
            log(QStringLiteral("key %1: repack failed: %2").arg(ki).arg(QString::fromUtf8(ee).trimmed()));
            continue;
        }

        // gpgsm import with the temp passphrase via loopback. The repacked p12 is
        // passed as a file arg; only the passphrase goes on stdin (fd 0).
        QByteArray io, ie;
        QStringList imp;
        imp << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
            << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
            << QStringLiteral("--import") << p12File;
        bool ok = runGpgsm(imp, passphrase.toUtf8() + "\n", &io, &ie, 90000);
        log(QStringLiteral("key %1 import: %2 %3").arg(ki).arg(ok ? "ok" : "FAIL")
            .arg(QString::fromUtf8(ie).trimmed()));
        if (ok) ++imported;
    }

    // 4) Import the CA chain AFTER the keys. gpgsm only lists/pairs a secret key
    //    once the issuer chain is present; importing the chain afterwards makes the
    //    just-imported private keys show up as usable secret-key certs.
    if (!chainPem.isEmpty()) {
        QByteArray io, ie;
        runGpgsm(QStringList() << QStringLiteral("--import"), chainPem, &io, &ie);
        log(QStringLiteral("chain import: %1").arg(QString::fromUtf8(ie).trimmed()));
    }

    // 5) Auto-complete the trust chain from the certs' own AIA data (download any
    //    missing issuer up to the self-signed root), then trust the roots.
    completeChainViaAia();
    updateTrustlist();

    emit certsChanged();
    if (imported > 0) emit importFinished(true, imported, QString());
    else emit importFinished(false, 0, QStringLiteral("no private key could be imported — check passphrase / see debug.log"));
}

// ---------------------------------------------------------------------------

void SmimeEngine::importCertFromFile(const QString &pathOrData)
{
    if (!m_available) { emit importFinished(false, 0, QStringLiteral("gpgsm not available")); return; }
    QString p = pathOrData;
    if (p.startsWith(QStringLiteral("file://"))) p = p.mid(7);
    QByteArray data;
    if (QFileInfo::exists(p)) { QFile f(p); if (f.open(QIODevice::ReadOnly)) { data = f.readAll(); f.close(); } }
    else data = pathOrData.toUtf8();
    if (data.isEmpty()) { emit importFinished(false, 0, QStringLiteral("empty input")); return; }

    // gpgsm --import accepts PEM/DER certs, PKCS#7 bundles AND signed CMS messages,
    // importing every certificate it finds (the signer cert + chain).
    QByteArray out, err;
    bool ok = runGpgsm(QStringList() << QStringLiteral("--import"), data, &out, &err);
    log(QStringLiteral("cert import: %1").arg(QString::fromUtf8(err).trimmed()));
    // Pull in the issuer chain up to the root (via the cert's AIA) and trust roots.
    completeChainViaAia();
    updateTrustlist();
    emit certsChanged();
    // Pull the "imported: N" count out of gpgsm's status text.
    int n = 0;
    const QString es = QString::fromUtf8(err);
    int idx = es.indexOf(QStringLiteral("imported:"));
    if (idx >= 0) n = es.mid(idx + 9).trimmed().section('\n', 0, 0).trimmed().toInt();
    if (ok) emit importFinished(true, n, QString());
    else    emit importFinished(false, 0, QString::fromUtf8(err).trimmed());
}

// --- working directly on a received QMF message ----------------------------

QString SmimeEngine::messageKind(int messageId)
{
    const QByteArray low = smimeRawMessage(messageId).toLower();
    if (low.isEmpty()) return QString();
    if (low.contains("pkcs7-mime")) {
        if (low.contains("signed-data")) return QStringLiteral("signed");
        return QStringLiteral("encrypted");          // enveloped-data
    }
    if (low.contains("pkcs7-signature")) return QStringLiteral("signed");
    return QString();
}

// Import the sender's cert(s) from the CMS of a signed message (no decryption).
void SmimeEngine::importCertFromMessage(int messageId)
{
    if (!m_available) { emit importFinished(false, 0, QStringLiteral("gpgsm not available")); return; }
    const QByteArray raw = smimeRawMessage(messageId);
    if (raw.isEmpty()) { emit importFinished(false, 0, QStringLiteral("message not downloaded yet")); return; }

    QByteArray der = smimePkcs7Der(raw, "pkcs7-signature");
    if (der.isEmpty()) der = smimePkcs7Der(raw, "pkcs7-mime");   // opaque signed-data
    if (der.isEmpty()) {
        emit importFinished(false, 0, QStringLiteral("no certificate here — encrypted mail? decrypt it to learn the sender's cert"));
        return;
    }
    QByteArray pem, e1;
    runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform")
                             << QStringLiteral("DER") << QStringLiteral("-print_certs"),
               der, &pem, &e1, 20000);
    if (pem.isEmpty()) { emit importFinished(false, 0, QStringLiteral("no certificates in the signature")); return; }
    QByteArray io, ie;
    bool ok = runGpgsm(QStringList() << QStringLiteral("--import"), pem, &io, &ie);
    log(QStringLiteral("sender cert import: %1").arg(QString::fromUtf8(ie).trimmed()));
    completeChainViaAia();
    updateTrustlist();
    emit certsChanged();
    int n = 0; const QString es = QString::fromUtf8(ie);
    int idx = es.indexOf(QStringLiteral("imported:"));
    if (idx >= 0) n = es.mid(idx + 9).trimmed().section('\n', 0, 0).trimmed().toInt();
    emit importFinished(ok, n, ok ? QString() : QString::fromUtf8(ie).trimmed());
}

void SmimeEngine::decryptMessage(int messageId, const QString &passphrase)
{
    if (!m_available) { emit decryptFinished(false, QString(), QString(), QStringLiteral("gpgsm not available")); return; }
    const QByteArray raw = smimeRawMessage(messageId);
    if (raw.isEmpty()) { emit decryptFinished(false, QString(), QString(), QStringLiteral("message not downloaded yet")); return; }
    const QByteArray der = smimePkcs7Der(raw, "pkcs7-mime");
    if (der.isEmpty()) { emit decryptFinished(false, QString(), QString(), QStringLiteral("no encrypted S/MIME part found")); return; }

    QByteArray inner, err;
    runGpgsm(QStringList() << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                           << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                           << QStringLiteral("--decrypt"),
             passphrase.toUtf8() + "\n" + der, &inner, &err, 90000);
    // Evaluate by OUTPUT, not exit code. gpgsm returns non-zero when ANY recipient's
    // key is missing — e.g. the message is also encrypted to a CO-RECIPIENT whose
    // secret key we don't hold (the encrypt-to-self copy is encrypted to the other
    // party AND to us) — even though OUR key decrypted it fine and produced the
    // plaintext. Same lesson as the PGP path (0.3.4). Only an EMPTY result is a real
    // failure (wrong passphrase / none of the recipients is us).
    if (inner.isEmpty()) { emit decryptFinished(false, QString(), QString(), QString::fromUtf8(err).trimmed()); return; }

    // The decrypted content may be: plain MIME, multipart/signed (cleartext + a
    // detached pkcs7-signature), OR an OPAQUE signed-data CMS (application/
    // pkcs7-mime; smime-type=signed-data) that ENCAPSULATES the real content. The
    // last case must be unwrapped, else the user just sees the pkcs7 wrapper.
    QByteArray content = inner;
    QByteArray certDer;
    const QByteArray low = inner.toLower();
    if (low.contains("pkcs7-mime")) {
        const QByteArray sd = smimePkcs7Der(inner, "pkcs7-mime");
        if (!sd.isEmpty()) {
            certDer = sd;   // signer certs live in this CMS
            const QString tmp = m_home + QStringLiteral("/tmp_sd.der");
            { QFile f(tmp); if (f.open(QIODevice::WriteOnly)) { f.write(sd); f.close(); } }
            QByteArray vout, verr;
            runOpenssl(QStringList() << QStringLiteral("smime") << QStringLiteral("-verify")
                                     << QStringLiteral("-noverify") << QStringLiteral("-inform")
                                     << QStringLiteral("DER") << QStringLiteral("-in") << tmp,
                       QByteArray(), &vout, &verr, 20000);
            QFile::remove(tmp);
            if (!vout.isEmpty()) content = vout;
        }
    } else if (low.contains("pkcs7-signature")) {
        certDer = smimePkcs7Der(inner, "pkcs7-signature");   // cleartext stays in `content`
    }

    // Stash the sender cert(s) for an explicit "Import" button (do NOT auto-import —
    // the user decides). signer == "cert-available" tells the UI to show the button.
    m_pendingSenderCertPem.clear();
    if (!certDer.isEmpty()) {
        QByteArray pem, e1;
        runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform")
                                 << QStringLiteral("DER") << QStringLiteral("-print_certs"),
                   certDer, &pem, &e1, 20000);
        if (!pem.isEmpty()) m_pendingSenderCertPem = pem;
    }
    // Tell the UI whether the sender cert is NEW (show import) or already present.
    QString signer;
    if (!m_pendingSenderCertPem.isEmpty())
        signer = certsAllInStore(m_pendingSenderCertPem) ? QStringLiteral("cert-present")
                                                         : QStringLiteral("cert-new");
    // Remember the signer certs for this message so "Encryption info" can show the
    // signature certs without a second passphrase prompt.
    m_lastDecMsgId = messageId;
    m_lastDecSignerPem = m_pendingSenderCertPem;
    // S/MIME mails carry their files inside the decrypted MIME too — extract them so
    // the UI can show/save them like PGP attachments (read via takeLastAttachments()).
    m_lastDecAttachments = smimeExtractAttachments(content, QString());   // in-memory, no part files
    emit decryptFinished(true, smimeReadableText(content), signer, QString());
}

bool SmimeEngine::certsAllInStore(const QByteArray &pem)
{
    QSet<QString> have;
    for (const QVariant &v : listCerts())
        have.insert(v.toMap().value(QStringLiteral("fpr")).toString().toUpper());
    const QList<QByteArray> certs = pemBlocks(pem, "CERTIFICATE");
    if (certs.isEmpty()) return false;
    for (const QByteArray &c : certs) {
        QByteArray o, e;
        runOpenssl(QStringList() << QStringLiteral("x509") << QStringLiteral("-noout")
                                 << QStringLiteral("-fingerprint") << QStringLiteral("-sha1"),
                   c, &o, &e, 10000);
        // "SHA1 Fingerprint=AA:BB:.." → 40-hex uppercase, matching gpgsm's fpr.
        QString fp = QString::fromUtf8(o).section('=', 1).trimmed();
        fp.remove(':'); fp = fp.toUpper();
        if (!fp.isEmpty() && !have.contains(fp)) return false;
    }
    return true;
}

QByteArray SmimeEngine::senderCertPemOf(int messageId)
{
    const QByteArray raw = smimeRawMessage(messageId);
    if (raw.isEmpty()) return QByteArray();
    QByteArray der = smimePkcs7Der(raw, "pkcs7-signature");
    if (der.isEmpty() && raw.toLower().contains("signed-data"))
        der = smimePkcs7Der(raw, "pkcs7-mime");
    if (der.isEmpty()) return QByteArray();
    QByteArray pem, e;
    runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform")
                             << QStringLiteral("DER") << QStringLiteral("-print_certs"),
               der, &pem, &e, 20000);
    return pem;
}

bool SmimeEngine::senderCertMissing(int messageId)
{
    if (!m_available) return false;
    const QByteArray pem = senderCertPemOf(messageId);
    if (pem.isEmpty()) return false;           // encrypted (cert is inside) or none
    return !certsAllInStore(pem);
}

void SmimeEngine::importPendingSenderCert()
{
    if (m_pendingSenderCertPem.isEmpty()) { emit importFinished(false, 0, QStringLiteral("no sender certificate available")); return; }
    QByteArray io, ie;
    bool ok = runGpgsm(QStringList() << QStringLiteral("--import"), m_pendingSenderCertPem, &io, &ie);
    log(QStringLiteral("sender cert import: %1").arg(QString::fromUtf8(ie).trimmed()));
    completeChainViaAia();
    updateTrustlist();
    emit certsChanged();
    int n = 0; const QString es = QString::fromUtf8(ie);
    int idx = es.indexOf(QStringLiteral("imported:"));
    if (idx >= 0) n = es.mid(idx + 9).trimmed().section('\n', 0, 0).trimmed().toInt();
    emit importFinished(ok, n, ok ? QString() : QString::fromUtf8(ie).trimmed());
}

QVariantList SmimeEngine::listCerts()
{
    QVariantList res;
    if (!m_available) return res;
    // hasSecret via KEYGRIP, not --list-secret-keys: gpgsm only lists a secret cert
    // once its chain fully validates, so --list-secret-keys reports 0 here even
    // though the private keys are present and usable (decrypt works). Instead match
    // each cert's keygrip against the .key files in private-keys-v1.d.
    QByteArray out, err;
    runGpgsm(QStringList() << QStringLiteral("--list-keys") << QStringLiteral("--with-colons")
                           << QStringLiteral("--with-keygrip"),
             QByteArray(), &out, &err);
    const QString keyDir = m_home + QStringLiteral("/private-keys-v1.d/");
    QVariantMap cur;
    for (const QByteArray &lr : out.split('\n')) {
        const QStringList f = QString::fromUtf8(lr).split(':');
        if (f.isEmpty()) continue;
        if (f[0] == QLatin1String("crt")) {
            if (!cur.isEmpty()) { res.append(cur); cur.clear(); }
            const QString usage = f.value(11);               // sS=sign eE=encrypt cC=CA
            cur[QStringLiteral("validity")] = f.value(1);
            cur[QStringLiteral("keyUsage")] = usage;
            cur[QStringLiteral("isCA")] = usage.contains('c', Qt::CaseInsensitive);
            cur[QStringLiteral("hasSecret")] = false;
        } else if (f[0] == QLatin1String("fpr")) {
            if (!cur.contains(QStringLiteral("fpr"))) {
                cur[QStringLiteral("fpr")] = f.value(9);
                // The fpr record's chaining field (12) holds the ISSUER's fingerprint;
                // equal to own fpr (or empty) ⇒ self-signed root.
                const QString chain = f.value(12);
                cur[QStringLiteral("chainId")] = chain;
                cur[QStringLiteral("isRoot")] = chain.isEmpty() || chain == f.value(9);
            }
        } else if (f[0] == QLatin1String("grp")) {
            const QString grp = f.value(9);
            if (!grp.isEmpty() && QFileInfo::exists(keyDir + grp + QStringLiteral(".key")))
                cur[QStringLiteral("hasSecret")] = true;
        } else if (f[0] == QLatin1String("uid")) {
            // Prefer an e-mail-looking UID over the raw DN.
            const QString u = f.value(9);
            if (u.contains('@') || !cur.contains(QStringLiteral("uid"))) cur[QStringLiteral("uid")] = u;
        }
    }
    if (!cur.isEmpty()) res.append(cur);
    return res;
}

QString SmimeEngine::exportCert(const QString &fingerprint)
{
    if (!m_available || fingerprint.isEmpty()) return QString();
    QByteArray out, err;
    runGpgsm(QStringList() << QStringLiteral("--armor") << QStringLiteral("--export") << fingerprint,
             QByteArray(), &out, &err);
    return QString::fromUtf8(out);
}

QString SmimeEngine::saveP12ToDocuments(const QString &fingerprint, const QString &passphrase)
{
    if (!m_available || fingerprint.isEmpty()) return QString();
    // gpgsm protects the exported .p12 with the SAME passphrase it reads from fd 0
    // to unlock the key (proven pattern, also used by signWithChain).
    QByteArray p12, err;
    if (!runGpgsm(QStringList() << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                                << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                                << QStringLiteral("--export-secret-key-p12") << fingerprint,
                  passphrase.toUtf8() + "\n", &p12, &err, 90000) || p12.isEmpty()) {
        log(QStringLiteral("p12 export failed: %1").arg(QString::fromUtf8(err).trimmed()));
        return QString();
    }
    QString dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + QStringLiteral("/Documents");
    QDir().mkpath(dir);
    const QString path = dir + QStringLiteral("/sfmail-smime-") + fingerprint.right(16) + QStringLiteral(".p12");
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return QString();
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    f.write(p12);
    f.close();
    log(QStringLiteral("p12 backup written to %1").arg(path));
    return path;
}

bool SmimeEngine::deleteCert(const QString &fingerprint)
{
    if (!m_available || fingerprint.isEmpty()) return false;
    // Collect the cert's keygrip(s) first, so we can drop the private key file too.
    QByteArray out, err;
    runGpgsm(QStringList() << QStringLiteral("--with-colons") << QStringLiteral("--with-keygrip")
                           << QStringLiteral("--list-keys") << fingerprint,
             QByteArray(), &out, &err);
    QStringList grips;
    for (const QByteArray &lr : out.split('\n')) {
        const QStringList f = QString::fromUtf8(lr).split(':');
        if (!f.isEmpty() && f[0] == QLatin1String("grp") && !f.value(9).isEmpty())
            grips << f.value(9);
    }
    // Delete the certificate from the keybox.
    QByteArray o2, e2;
    const bool ok = runGpgsm(QStringList() << QStringLiteral("--yes")
                                           << QStringLiteral("--delete-keys") << fingerprint,
                             QByteArray(), &o2, &e2);
    // Remove the private key file(s), if present.
    const QString keyDir = m_home + QStringLiteral("/private-keys-v1.d/");
    for (const QString &g : grips) QFile::remove(keyDir + g + QStringLiteral(".key"));
    log(QStringLiteral("deleteCert %1: %2 %3").arg(fingerprint).arg(ok ? "ok" : "FAIL")
        .arg(QString::fromUtf8(e2).trimmed()));
    emit certsChanged();
    return ok;
}

QVariantMap SmimeEngine::certEntry(const QString &fpr, const QVariantList &all)
{
    QVariantMap e;
    e[QStringLiteral("fpr")] = fpr;
    QVariantMap m;
    for (const QVariant &v : all) {
        const QVariantMap mm = v.toMap();
        if (mm.value(QStringLiteral("fpr")).toString() == fpr) { m = mm; break; }
    }
    if (m.isEmpty()) {
        e[QStringLiteral("inStore")] = false;
        e[QStringLiteral("subject")] = QStringLiteral("(not in your certificate store)");
        e[QStringLiteral("chain")] = QVariantList();
        return e;
    }
    e[QStringLiteral("inStore")]  = true;
    e[QStringLiteral("subject")]  = m.value(QStringLiteral("uid"));
    e[QStringLiteral("hasSecret")]= m.value(QStringLiteral("hasSecret"));
    e[QStringLiteral("keyUsage")] = m.value(QStringLiteral("keyUsage"));
    e[QStringLiteral("validity")] = m.value(QStringLiteral("validity"));
    // Walk the issuer chain up to the (self-signed) root.
    QVariantList chain;
    QSet<QString> seen; seen << fpr;
    QString cur = m.value(QStringLiteral("chainId")).toString();
    for (int g = 0; g < 16 && !cur.isEmpty() && !seen.contains(cur); ++g) {
        seen << cur;
        QVariantMap im;
        for (const QVariant &v : all) {
            const QVariantMap mm = v.toMap();
            if (mm.value(QStringLiteral("fpr")).toString() == cur) { im = mm; break; }
        }
        if (im.isEmpty()) break;
        QVariantMap ce;
        ce[QStringLiteral("subject")] = im.value(QStringLiteral("uid"));
        ce[QStringLiteral("fpr")]     = cur;
        ce[QStringLiteral("role")]    = im.value(QStringLiteral("isRoot")).toBool()
                                        ? QStringLiteral("Root CA") : QStringLiteral("Intermediate CA");
        chain.append(ce);
        if (im.value(QStringLiteral("isRoot")).toBool()) break;
        cur = im.value(QStringLiteral("chainId")).toString();
    }
    e[QStringLiteral("chain")] = chain;
    return e;
}

QVariantMap SmimeEngine::messageCertInfo(int messageId, const QString &passphrase)
{
    QVariantMap res;
    res[QStringLiteral("format")]        = QStringLiteral("S/MIME (PKI)");
    res[QStringLiteral("encRecipients")] = QVariantList();
    res[QStringLiteral("signCerts")]     = QVariantList();
    res[QStringLiteral("debug")]         = QString();
    res[QStringLiteral("canDecrypt")]    = false;
    if (!m_available) { res[QStringLiteral("error")] = QStringLiteral("gpgsm not available"); return res; }
    const QByteArray raw = smimeRawMessage(messageId);
    if (raw.isEmpty()) { res[QStringLiteral("error")] = QStringLiteral("message not downloaded yet"); return res; }

    const QByteArray low = raw.toLower();
    const bool encrypted = low.contains("enveloped-data");
    const QByteArray der = smimePkcs7Der(raw, "pkcs7-mime");
    const QVariantList all = listCerts();
    QByteArray dbg;
    QByteArray inner;   // decrypted content (if any)

    if (encrypted && !der.isEmpty()) {
        QByteArray decErr;
        runGpgsm(QStringList() << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                               << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                               << QStringLiteral("--decrypt"),
                 passphrase.toUtf8() + "\n" + der, &inner, &decErr, 90000);
        dbg += "== gpgsm --decrypt (stderr) ==\n" + decErr + "\n";
        // Parse "gpgsm: encrypted to <algo> key <FPR>" lines (printed for EVERY
        // recipient even when we have no secret key for some of them).
        QStringList fprs; QVariantMap algoOf;
        for (const QByteArray &lr : decErr.split('\n')) {
            const QString line = QString::fromUtf8(lr);
            const int k = line.indexOf(QStringLiteral("key "));
            const int a = line.indexOf(QStringLiteral("encrypted to"));
            if (a >= 0 && k > a) {
                const QString fpr = line.mid(k + 4).trimmed().section(' ', 0, 0);
                const QString algo = line.mid(a + 12, k - (a + 12)).trimmed();
                if (!fpr.isEmpty() && !fprs.contains(fpr)) { fprs << fpr; algoOf[fpr] = algo; }
            }
        }
        QVariantList recs;
        for (const QString &fpr : fprs) {
            QVariantMap e = certEntry(fpr, all);
            e[QStringLiteral("algo")] = algoOf.value(fpr);
            recs << e;
        }
        res[QStringLiteral("encRecipients")] = recs;
        res[QStringLiteral("canDecrypt")] = !inner.isEmpty();
    }

    // Signature certs (openssl "subject=/issuer=" + PEM format). Source order:
    //   1) the just-decrypted inner signed-data (when a passphrase was supplied),
    //   2) a sign-only (unencrypted) message's signed-data straight away,
    //   3) the certs cached from a PRIOR decrypt of this same message — so the
    //      "Encryption info" view needs no second passphrase (the user already
    //      decrypted the mail), matching the PGP behaviour.
    QByteArray signerPem;
    QByteArray signedDer;
    if (!inner.isEmpty() && inner.toLower().contains("pkcs7-mime"))
        signedDer = smimePkcs7Der(inner, "pkcs7-mime");
    else if (!encrypted && low.contains("signed-data"))
        signedDer = der;
    if (!signedDer.isEmpty()) {
        QByteArray e2;
        runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform")
                                 << QStringLiteral("DER") << QStringLiteral("-print_certs"),
                   signedDer, &signerPem, &e2, 20000);
        dbg += "== signed-data embedded certs ==\n" + signerPem + "\n";
    } else if (encrypted && inner.isEmpty()) {
        if (messageId == m_lastDecMsgId && !m_lastDecSignerPem.isEmpty()) {
            signerPem = m_lastDecSignerPem;
            dbg += "== signature certs (from last decrypt) ==\n" + signerPem + "\n";
        } else {
            res[QStringLiteral("signNote")] =
                QStringLiteral("Decrypt the message first to list its signature certificates.");
        }
    }
    if (!signerPem.isEmpty()) {
        QVariantList sc; QVariantMap cur2;
        for (const QByteArray &lr : signerPem.split('\n')) {
            const QString line = QString::fromUtf8(lr).trimmed();
            if (line.startsWith(QStringLiteral("subject="))) {
                if (!cur2.isEmpty()) { sc << cur2; cur2.clear(); }
                cur2[QStringLiteral("subject")] = line.mid(8).trimmed();
            } else if (line.startsWith(QStringLiteral("issuer="))) {
                cur2[QStringLiteral("issuer")] = line.mid(7).trimmed();
            }
        }
        if (!cur2.isEmpty()) sc << cur2;
        res[QStringLiteral("signCerts")] = sc;
    }

    res[QStringLiteral("debug")] = QString::fromUtf8(dbg);
    return res;
}

// --- sending ---------------------------------------------------------------

QString SmimeEngine::extKeyUsage(const QString &fingerprint)
{
    if (fingerprint.isEmpty()) return QString();
    QByteArray out, err;
    runGpgsm(QStringList() << QStringLiteral("--list-keys") << fingerprint,
             QByteArray(), &out, &err);
    for (const QByteArray &lr : out.split('\n')) {
        const QString line = QString::fromUtf8(lr).trimmed();
        if (line.startsWith(QLatin1String("ext key usage:"), Qt::CaseInsensitive))
            return line.mid(QStringLiteral("ext key usage:").length()).trimmed();
    }
    return QString();   // no extKeyUsage extension ⇒ unrestricted
}

QString SmimeEngine::ownCertFpr(const QString &email, char usage)
{
    const QString want = (usage == 'e') ? QStringLiteral("e") : QStringLiteral("s");
    const QVariantList certs = listCerts();
    // For SIGNING the cert must be valid for "emailProtection". The
    // Volksverschlüsselung issues THREE certs for the same address: a signing cert
    // (digitalSignature+nonRepudiation, EKU emailProtection), an encryption cert
    // (keyEncipherment, EKU emailProtection) and an AUTHENTICATION/login cert
    // (digitalSignature, EKU clientAuth ONLY). The auth cert also reports key usage
    // 's', so "first cert that can sign" picks it — and Outlook/Windows then reject
    // the signature ("certificate not valid for the selected purpose": EKU is
    // clientAuth, not emailProtection). Thunderbird filters it out the same way and
    // never offers it. So we additionally require the EKU to permit emailProtection.
    // [[keys-immer-per-fingerprint]]
    const bool needEmail = (usage == 's');
    QString fallback;   // EKU-unrestricted match; used only if no emailProtection cert exists
    for (int pass = 0; pass < 2; ++pass) {   // pass 0: match the address; pass 1: any
        for (const QVariant &v : certs) {
            const QVariantMap m = v.toMap();
            if (!m.value(QStringLiteral("hasSecret")).toBool()) continue;
            if (!m.value(QStringLiteral("keyUsage")).toString().toLower().contains(want)) continue;
            if (pass == 0 && !email.isEmpty()
                && !m.value(QStringLiteral("uid")).toString().contains(email, Qt::CaseInsensitive)) continue;
            const QString fpr = m.value(QStringLiteral("fpr")).toString();
            if (!needEmail) return fpr;
            const QString eku = extKeyUsage(fpr);
            if (eku.contains(QLatin1String("emailProtection"), Qt::CaseInsensitive))
                return fpr;                       // the real signing cert — done
            if (eku.isEmpty() && fallback.isEmpty())
                fallback = fpr;                   // no EKU restriction ⇒ usable as fallback
            // EKU present but no emailProtection (e.g. clientAuth only) ⇒ skip it
        }
        if (!fallback.isEmpty()) return fallback;
    }
    return fallback;
}

bool SmimeEngine::hasCertFor(const QString &email)
{
    if (!m_available || email.isEmpty()) return false;
    QByteArray out, err;
    runGpgsm(QStringList() << QStringLiteral("--list-keys") << QStringLiteral("--with-colons") << email,
             QByteArray(), &out, &err);
    for (const QByteArray &lr : out.split('\n'))
        if (lr.startsWith("crt:")) return true;
    return false;
}

QByteArray SmimeEngine::signWithChain(const QByteArray &inner, const QString &signFpr,
                                      const QString &fromAddr, const QString &passphrase,
                                      QByteArray *errOut)
{
    QByteArray dummy; QByteArray &err = errOut ? *errOut : dummy;
    QTemporaryDir td(m_home + QStringLiteral("/sign-XXXXXX"));
    if (!td.isValid()) { err = "no temp dir"; return QByteArray(); }
    const QString p12f  = td.path() + QStringLiteral("/sign.p12");
    const QString pemf  = td.path() + QStringLiteral("/sign.pem");
    const QString certf = td.path() + QStringLiteral("/extra.pem");
    const QString cf    = td.path() + QStringLiteral("/content");
    const QString sigf  = td.path() + QStringLiteral("/sig.der");

    // 1) Export the signing key+cert out of gpgsm as a (binary) PKCS#12. gpgsm
    //    protects the export with the SAME passphrase it reads from fd 0 to unlock.
    QByteArray p12, e1;
    if (!runGpgsm(QStringList() << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                                << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                                << QStringLiteral("--export-secret-key-p12") << signFpr,
                  passphrase.toUtf8() + "\n", &p12, &e1, 90000) || p12.isEmpty()) {
        err = (QStringLiteral("key export failed: ") + QString::fromUtf8(e1).trimmed()).toUtf8(); return QByteArray();
    }
    { QFile f(p12f); if (!f.open(QIODevice::WriteOnly)) { err = "write p12"; return QByteArray(); } f.write(p12); }

    // 2) PKCS#12 → PEM (key + signer cert). gpgsm exports with legacy RC2, so OpenSSL
    //    3.x needs -legacy to read it.
    QStringList o; o << QStringLiteral("pkcs12") << QStringLiteral("-in") << p12f
                     << QStringLiteral("-nodes");
    if (opensslHasLegacy()) o << QStringLiteral("-legacy");
    o << QStringLiteral("-passin") << (QStringLiteral("pass:") + passphrase)
      << QStringLiteral("-out") << pemf;
    QByteArray oo, oe;
    if (!runOpenssl(o, QByteArray(), &oo, &oe, 30000) || !QFileInfo::exists(pemf)) {
        err = (QStringLiteral("p12→pem failed: ") + QString::fromUtf8(oe).trimmed()).toUtf8(); return QByteArray();
    }

    // 3) Extra certs to embed: the sender's ENCRYPTION cert + ITS OWN issuer chain
    //    (intermediate + root) — NOT every CA in the store, so we don't leak an
    //    unrelated identity's chain (e.g. a second, employer cert). The signer cert
    //    is added by -signer; signer and encryption cert share the same chain.
    QByteArray extra;
    const QVariantList allCerts = listCerts();
    QStringList want;
    const QString encFpr = ownCertFpr(fromAddr, 'e');
    if (!encFpr.isEmpty()) {
        want << encFpr;
        QString cur = encFpr;
        for (int guard = 0; guard < 16; ++guard) {
            QVariantMap m;
            for (const QVariant &v : allCerts) {
                const QVariantMap mm = v.toMap();
                if (mm.value(QStringLiteral("fpr")).toString() == cur) { m = mm; break; }
            }
            if (m.isEmpty() || m.value(QStringLiteral("isRoot")).toBool()) break;   // reached root
            const QString issuer = m.value(QStringLiteral("chainId")).toString();
            if (issuer.isEmpty() || issuer == cur) break;
            want << issuer;
            cur = issuer;
        }
    }
    for (const QString &fpr : want) extra += exportCert(fpr).toUtf8();
    if (extra.isEmpty()) { err = "no encryption cert / chain to embed"; return QByteArray(); }
    { QFile f(certf); if (f.open(QIODevice::WriteOnly)) f.write(extra); }
    { QFile f(cf);    if (f.open(QIODevice::WriteOnly)) f.write(inner); }

    // 4) Opaque CMS signature with openssl, embedding -certfile. -binary keeps the
    //    content byte-exact (no CRLF canonicalisation).
    QStringList s; s << QStringLiteral("cms") << QStringLiteral("-sign")
                     << QStringLiteral("-signer") << pemf << QStringLiteral("-inkey") << pemf
                     << QStringLiteral("-certfile") << certf
                     << QStringLiteral("-nodetach") << QStringLiteral("-binary")
                     << QStringLiteral("-outform") << QStringLiteral("DER")
                     << QStringLiteral("-in") << cf << QStringLiteral("-out") << sigf;
    QByteArray so, se;
    if (!runOpenssl(s, QByteArray(), &so, &se, 60000) || !QFileInfo::exists(sigf)) {
        err = (QStringLiteral("cms sign failed: ") + QString::fromUtf8(se).trimmed()).toUtf8(); return QByteArray();
    }
    QFile f(sigf);
    if (!f.open(QIODevice::ReadOnly)) { err = "read sig"; return QByteArray(); }
    return f.readAll();
}

void SmimeEngine::sendSmime(int accountId, const QString &subject,
                            const QStringList &to, const QStringList &cc,
                            const QStringList &bcc, const QString &body,
                            const QVariantList &attachments,
                            bool encrypt, bool sign, const QString &passphrase)
{
    if (!m_available) { emit sendFinished(false, QStringLiteral("S/MIME not available")); return; }
    const QMailAccountId accId(static_cast<quint64>(accountId));
    QMailAccount account(accId);
    const QString fromAddr = account.fromAddress().address();

    QString signFpr;
    if (sign) {
        signFpr = ownCertFpr(fromAddr, 's');
        if (signFpr.isEmpty()) { emit sendFinished(false, QStringLiteral("No S/MIME signing certificate for %1").arg(fromAddr)); return; }
    }

    const qint64 stamp = QDateTime::currentMSecsSinceEpoch();
    const QByteArray inner = buildInnerMime(body, attachments, stamp);

    // 1) Optional sign → opaque signed-data CMS, wrapped as a pkcs7-mime entity
    //    (this becomes the plaintext that is then enveloped — the nested structure
    //    our own decrypt understands).
    QByteArray content = inner;
    if (sign) {
        // Preferred: sign via openssl so we can ALSO embed the encryption cert + chain
        // (so recipients/Outlook can reply encrypted, like Thunderbird does).
        QByteArray cerr;
        QByteArray sd = signWithChain(inner, signFpr, fromAddr, passphrase, &cerr);
        if (sd.isEmpty()) {
            // Fallback: plain gpgsm sign (signer cert only) so sending still works.
            log(QStringLiteral("signWithChain failed (%1) — falling back to gpgsm --sign")
                .arg(QString::fromUtf8(cerr).trimmed()));
            QTemporaryDir td(m_home + QStringLiteral("/send-XXXXXX"));
            const QString cf = td.path() + QStringLiteral("/content");
            { QFile f(cf); if (f.open(QIODevice::WriteOnly)) { f.write(inner); f.close(); } }
            QByteArray serr;
            QStringList a;
            a << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
              << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
              << QStringLiteral("--local-user") << signFpr
              << QStringLiteral("--sign") << QStringLiteral("--output") << QStringLiteral("-") << cf;
            if (!runGpgsm(a, passphrase.toUtf8() + "\n", &sd, &serr, 90000) || sd.isEmpty()) {
                emit sendFinished(false, QStringLiteral("Signing failed: %1").arg(QString::fromUtf8(serr).trimmed()));
                return;
            }
        }
        content = pkcs7MimeEntity(sd, "signed-data");
    }

    // 2) Optional encrypt → enveloped-data CMS to every recipient + self.
    QByteArray outerBody;
    if (encrypt) {
        QStringList recips = to; recips += cc; recips += bcc;
        if (!fromAddr.isEmpty()) recips << fromAddr;   // encrypt-to-self for a readable Sent copy
        QStringList args;
        for (const QString &r : recips) if (!r.trimmed().isEmpty()) args << QStringLiteral("-r") << r.trimmed();
        args << QStringLiteral("--encrypt") << QStringLiteral("--output") << QStringLiteral("-");
        QByteArray env, eerr;
        if (!runGpgsm(args, content, &env, &eerr, 90000) || env.isEmpty()) {
            emit sendFinished(false, QStringLiteral("Encryption failed (recipient certificate missing or untrusted?): %1")
                              .arg(QString::fromUtf8(eerr).trimmed()));
            return;
        }
        outerBody = pkcs7MimeEntity(env, "enveloped-data");
    } else {
        outerBody = content;   // sign-only: the pkcs7-mime signed-data IS the body
    }

    qWarning() << "[smime] send: built CMS (" << outerBody.size() << "bytes), deferring QMF";
    QByteArray rfc;
    rfc += "From: " + account.fromAddress().toString().toUtf8() + "\r\n";
    rfc += "To: " + to.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!cc.isEmpty())  rfc += "Cc: " + cc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    if (!bcc.isEmpty()) rfc += "Bcc: " + bcc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
    rfc += "Subject: " + subject.toUtf8() + "\r\n";
    rfc += "Date: " + QMailTimeStamp::currentDateTime().toString().toUtf8() + "\r\n";
    QString dom = fromAddr.section('@', 1).trimmed(); if (dom.isEmpty()) dom = QStringLiteral("localhost");
    rfc += "Message-ID: <" + QByteArray::number(QDateTime::currentMSecsSinceEpoch())
         + ".sm@" + dom.toUtf8() + ">\r\n";
    rfc += "User-Agent: harbour-sfmail\r\n";
    rfc += "MIME-Version: 1.0\r\n";
    rfc += outerBody;

    const bool hasAtt = !attachments.isEmpty();
    QTimer::singleShot(0, this, [this, accId, rfc, hasAtt]() { smimeStoreAndTransmit(accId, rfc, hasAtt); });
}

void SmimeEngine::smimeStoreAndTransmit(const QMailAccountId &accId, const QByteArray &rfc, bool hasAttachments)
{
    QMailAccount account(accId);
    QMailMessage msg = QMailMessage::fromRfc2822(rfc);
    msg.setParentAccountId(accId);
    QMailFolderId outbox = account.standardFolder(QMailFolder::OutboxFolder);
    if (!outbox.isValid()) outbox = QMailFolderId(static_cast<quint64>(1));
    msg.setParentFolderId(outbox);
    msg.setStatus(QMailMessage::Outgoing, true);
    msg.setStatus(QMailMessage::ContentAvailable, true);
    msg.setStatus(QMailMessage::Read, true);
    msg.setStatus(QMailMessage::Outbox, true);
    msg.setStatus(QMailMessage::HasAttachments, hasAttachments);
    if (!QMailStore::instance()->addMessage(&msg)) {
        emit sendFinished(false, QStringLiteral("Could not store the message in the outbox."));
        return;
    }
    qWarning() << "[smime] send: stored msg" << msg.id().toULongLong() << "in outbox — queued";
    emit sendFinished(true, QString());
    if (!m_tx) {
        m_tx = new QMailTransmitAction(this);
        connect(m_tx, &QMailTransmitAction::activityChanged, this,
                [this](QMailServiceAction::Activity a) {
            if (a == QMailServiceAction::Failed)
                qWarning() << "[smime] send: transmit Failed:" << m_tx->status().text;
        });
    }
    m_tx->transmitMessages(accId);
}

void SmimeEngine::wipeStore()
{
    QDir d(m_home);
    // Remove keybox, private keys, trustlist — but keep the dir.
    const QStringList kill = { QStringLiteral("pubring.kbx"), QStringLiteral("trustlist.txt") };
    for (const QString &k : kill) QFile::remove(m_home + QStringLiteral("/") + k);
    QDir(m_home + QStringLiteral("/private-keys-v1.d")).removeRecursively();
    log(QStringLiteral("store wiped"));
    emit certsChanged();
}

// ---------------------------------------------------------------------------
// Decrypt (Stufe 1, milestone 2) + round-trip self-test
// ---------------------------------------------------------------------------

void SmimeEngine::decryptFile(const QString &pathOrPkcs7, const QString &passphrase)
{
    if (!m_available) { emit decryptFinished(false, QString(), QString(), QStringLiteral("gpgsm not available")); return; }
    QByteArray data;
    QString p = pathOrPkcs7;
    if (p.startsWith(QStringLiteral("file://"))) p = p.mid(7);
    if (QFileInfo::exists(p)) { QFile f(p); if (f.open(QIODevice::ReadOnly)) { data = f.readAll(); f.close(); } }
    else data = pathOrPkcs7.toUtf8();
    if (data.isEmpty()) { emit decryptFinished(false, QString(), QString(), QStringLiteral("empty input")); return; }

    QByteArray out, err;
    QStringList a;
    a << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
      << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
      << QStringLiteral("--decrypt");
    // gpgsm reads the passphrase from fd 0 first; feed passphrase then the CMS.
    bool ok = runGpgsm(a, passphrase.toUtf8() + "\n" + data, &out, &err, 90000);
    if (ok && !out.isEmpty())
        emit decryptFinished(true, QString::fromUtf8(out), QString(), QString());
    else
        emit decryptFinished(false, QString(), QString(), QString::fromUtf8(err).trimmed());
}

void SmimeEngine::roundTripTest(const QString &passphrase)
{
    if (!m_available) { emit roundTripFinished(false, QString(), QStringLiteral("gpgsm not available")); return; }
    // Try each secret-key cert: only the keyEncipherment one accepts --encrypt;
    // detecting it by usage flags is brittle, so just attempt all and succeed on
    // the first that encrypts AND decrypts back (matches the manual proof).
    const QVariantList certs = listCerts();
    const QByteArray sample = "S/MIME round-trip OK\n";
    QString lastErr = QStringLiteral("no secret-key cert in store");
    for (const QVariant &v : certs) {
        const QVariantMap m = v.toMap();
        if (!m.value(QStringLiteral("hasSecret")).toBool()) continue;
        const QString fpr = m.value(QStringLiteral("fpr")).toString();
        if (fpr.isEmpty()) continue;

        QByteArray cms, err;
        QStringList enc;
        enc << QStringLiteral("--armor") << QStringLiteral("-r") << fpr << QStringLiteral("--encrypt");
        if (!runGpgsm(enc, sample, &cms, &err, 60000) || cms.isEmpty()) {
            lastErr = QStringLiteral("encrypt: %1").arg(QString::fromUtf8(err).trimmed());
            continue;   // not an encryption cert — try the next
        }
        QByteArray back, derr;
        QStringList dec;
        dec << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
            << QStringLiteral("--passphrase-fd") << QStringLiteral("0") << QStringLiteral("--decrypt");
        bool ok = runGpgsm(dec, passphrase.toUtf8() + "\n" + cms, &back, &derr, 90000);
        if (ok && back.contains("round-trip OK")) {
            log(QStringLiteral("round-trip OK via %1").arg(fpr));
            emit roundTripFinished(true, QString::fromUtf8(back).trimmed(), QString());
            return;
        }
        lastErr = QStringLiteral("decrypt: %1").arg(QString::fromUtf8(derr).trimmed());
    }
    emit roundTripFinished(false, QString(), lastErr);
}
