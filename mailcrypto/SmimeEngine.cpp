#include "SmimeEngine.h"
#include <qmailnamespace.h>

#include <QProcess>
#include <QUuid>
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
#include <QSettings>
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
    // Ask QMF where its store lives instead of assuming a fixed dot-directory:
    // the location differs between installations (legacy ~/.qmf vs. the XDG data
    // directory on newer systems), and a wrong guess makes every S/MIME message
    // look like an empty plain one.
    const QString dbPath = QDir::cleanPath(QMail::dataPath())
                           + QStringLiteral("/database/qmailstore.db");
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
                         : (QDir::cleanPath(QMail::dataPath()) + QStringLiteral("/mail/") + mf);
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
// Content-Transfer-Encoding. Some clients commonly send iso-8859-1/windows-1252 with
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

// Two attachments may legitimately carry the same file name. Writing both under
// that name leaves two list entries pointing at one file, so the second silently
// replaces the first — the reader then opens the wrong document.
static QString smimeUniquePath(const QString &dir, const QString &name)
{
    QString candidate = dir + QStringLiteral("/") + name;
    if (!QFileInfo::exists(candidate)) return candidate;
    QString stem = name, ext;
    const int dot = name.lastIndexOf(QLatin1Char('.'));
    if (dot > 0) { stem = name.left(dot); ext = name.mid(dot); }
    for (int i = 1; i < 1000; ++i) {
        candidate = dir + QStringLiteral("/") + stem + QStringLiteral("-%1").arg(i) + ext;
        if (!QFileInfo::exists(candidate)) return candidate;
    }
    return candidate;
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

// RFC 2047 encoded words ("=?utf-8?Q?...?=") appear wherever a header carries
// non-ASCII text — including an attachment's file name. Undecoded they reach
// the user as gibberish and, worse, become the name of a file written to disk.
// Adjacent encoded words are joined without the whitespace between them, as the
// standard requires.
static QString decodeEncodedWords(const QString &in)
{
    if (!in.contains(QStringLiteral("=?"))) return in;
    QString out;
    int pos = 0;
    bool lastWasWord = false;
    while (pos < in.length()) {
        const int start = in.indexOf(QStringLiteral("=?"), pos);
        if (start < 0) { out += in.mid(pos); break; }
        // charset ? encoding ? text ?=
        const int q1 = in.indexOf(QLatin1Char('?'), start + 2);
        const int q2 = q1 > 0 ? in.indexOf(QLatin1Char('?'), q1 + 1) : -1;
        const int end = q2 > 0 ? in.indexOf(QStringLiteral("?="), q2 + 1) : -1;
        if (q1 < 0 || q2 != q1 + 2 || end < 0) {          // not a well-formed word
            out += in.mid(pos, start - pos + 2);
            pos = start + 2;
            lastWasWord = false;
            continue;
        }
        const QString between = in.mid(pos, start - pos);
        // Whitespace BETWEEN two encoded words is separator, not content.
        if (!(lastWasWord && between.trimmed().isEmpty())) out += between;

        const QString charset = in.mid(start + 2, q1 - start - 2);
        const QChar enc = in.at(q1 + 1).toUpper();
        const QByteArray raw = in.mid(q2 + 1, end - q2 - 1).toLatin1();
        QByteArray bytes;
        if (enc == QLatin1Char('B')) {
            bytes = QByteArray::fromBase64(raw);
        } else if (enc == QLatin1Char('Q')) {
            for (int i = 0; i < raw.size(); ++i) {
                const char c = raw.at(i);
                if (c == '_') { bytes.append(' '); }
                else if (c == '=' && i + 2 < raw.size()) {
                    bool ok = false;
                    const int v = raw.mid(i + 1, 2).toInt(&ok, 16);
                    if (ok) { bytes.append(char(v)); i += 2; }
                    else bytes.append(c);
                } else bytes.append(c);
            }
        } else {
            out += in.mid(start, end + 2 - start);        // unknown encoding: verbatim
            pos = end + 2;
            lastWasWord = true;
            continue;
        }
        QTextCodec *codec = QTextCodec::codecForName(charset.toLatin1());
        out += codec ? codec->toUnicode(bytes) : QString::fromUtf8(bytes);
        pos = end + 2;
        lastWasWord = true;
    }
    return out;
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
    return decodeEncodedWords(v);
}

// --- MIME structure (byte-exact) ----------------------------------------------
// The S/MIME plumbing below never searches the whole document for a keyword:
// what a message IS is decided by its Content-Type header, and parts are cut
// at their boundaries with their bytes untouched — a detached signature only
// verifies over the exact bytes that were signed.

// Split "headers\r\n\r\nbody" (or LF variant). Header block without the blank line.
static void smimeSplitHeadBody(const QByteArray &mime, QByteArray *hdr, QByteArray *body)
{
    int sep = mime.indexOf("\r\n\r\n"); int sl = 4;
    if (sep < 0) { sep = mime.indexOf("\n\n"); sl = 2; }
    if (sep < 0) { *hdr = mime; body->clear(); return; }
    *hdr = mime.left(sep);
    *body = mime.mid(sep + sl);
}

// The parts of a multipart body, each as raw "headers + blank line + body" bytes
// exactly as they appear between the boundary lines (the line break that
// precedes a boundary belongs to the boundary, per RFC 2046, and is dropped).
static QList<QByteArray> smimeSplitParts(const QByteArray &body, const QString &boundary)
{
    QList<QByteArray> parts;
    if (boundary.isEmpty()) return parts;
    const QByteArray delim = "--" + boundary.toUtf8();
    int pos = 0, start = -1;
    for (int guard = 0; guard < 4096; ++guard) {
        int d = body.indexOf(delim, pos);
        if (d < 0) break;
        if (d > 0 && body.at(d - 1) != '\n') { pos = d + delim.size(); continue; }   // not at a line start
        int lineEnd = body.indexOf('\n', d);
        const QByteArray rest = body.mid(d + delim.size(), lineEnd < 0 ? -1 : lineEnd - d - delim.size()).trimmed();
        if (!rest.isEmpty() && rest != "--") { pos = d + delim.size(); continue; }  // boundary is a prefix of another token
        if (start >= 0) {
            int end = d;
            if (end > start && body.at(end - 1) == '\n') { --end; if (end > start && body.at(end - 1) == '\r') --end; }
            parts.append(body.mid(start, end - start));
        }
        if (rest == "--" || lineEnd < 0) break;
        start = lineEnd + 1;
        pos = start;
    }
    return parts;
}

// Decode a leaf body according to its Content-Transfer-Encoding.
static QByteArray smimeDecodeBody(const QByteArray &body, const QString &cte)
{
    const QString e = cte.toLower();
    if (e.contains(QStringLiteral("base64"))) {
        QByteArray compact; compact.reserve(body.size());
        for (const char c : body)
            if (c != '\r' && c != '\n' && c != ' ' && c != '\t') compact.append(c);
        return QByteArray::fromBase64(compact);
    }
    if (e.contains(QStringLiteral("quoted-printable"))) return decodeQuotedPrintable(body);
    return body;
}

// What an S/MIME message is, read from its Content-Type headers only.
//   kind: "encrypted" | "signed-opaque" | "signed-detached" | ""
//   cms:  the DER of the CMS object (enveloped/signed data, or the detached signature)
//   signedContent: for "signed-detached" the raw bytes the signature covers
struct SmimeStructure {
    QString kind;
    QByteArray cms;
    QByteArray signedContent;
};

static SmimeStructure smimeInspectMime(const QByteArray &mime, int depth)
{
    SmimeStructure st;
    if (depth > 2 || mime.isEmpty()) return st;
    QByteArray hdr, body;
    smimeSplitHeadBody(mime, &hdr, &body);
    const QString ctFull = smimeHeaderField(hdr, "content-type");
    const QString ct = ctFull.section(';', 0, 0).trimmed().toLower();
    const QString cte = smimeHeaderField(hdr, "content-transfer-encoding");

    if (ct == QLatin1String("application/pkcs7-mime") || ct == QLatin1String("application/x-pkcs7-mime")) {
        const QString smimeType = smimeParam(ctFull, QStringLiteral("smime-type")).toLower();
        st.kind = (smimeType == QLatin1String("signed-data")) ? QStringLiteral("signed-opaque")
                                                              : QStringLiteral("encrypted");
        st.cms = smimeDecodeBody(body, cte);
        return st;
    }
    if (ct == QLatin1String("multipart/signed")) {
        const QString proto = smimeParam(ctFull, QStringLiteral("protocol")).toLower();
        if (!proto.contains(QStringLiteral("pkcs7-signature"))) return st;   // e.g. PGP/MIME
        const QList<QByteArray> parts = smimeSplitParts(body, smimeParam(ctFull, QStringLiteral("boundary")));
        if (parts.size() < 2) return st;
        for (int i = 1; i < parts.size(); ++i) {
            QByteArray ph, pb;
            smimeSplitHeadBody(parts.at(i), &ph, &pb);
            const QString pct = smimeHeaderField(ph, "content-type").section(';', 0, 0).trimmed().toLower();
            if (pct.contains(QStringLiteral("pkcs7-signature"))) {
                st.kind = QStringLiteral("signed-detached");
                st.cms = smimeDecodeBody(pb, smimeHeaderField(ph, "content-transfer-encoding"));
                st.signedContent = parts.at(0);
                return st;
            }
        }
        return st;
    }
    // Some gateways wrap the S/MIME object as the first part of a multipart/mixed.
    if (ct == QLatin1String("multipart/mixed")) {
        const QList<QByteArray> parts = smimeSplitParts(body, smimeParam(ctFull, QStringLiteral("boundary")));
        if (!parts.isEmpty()) return smimeInspectMime(parts.at(0), depth + 1);
    }
    return st;
}

static SmimeStructure smimeInspect(const QByteArray &raw) { return smimeInspectMime(raw, 0); }

// DER of the CMS object of the given flavour ("pkcs7-mime" = enveloped or opaque
// signed data, "pkcs7-signature" = detached signature), located by structure.
static QByteArray smimePkcs7Der(const QByteArray &raw, const QByteArray &mimeMatch)
{
    const SmimeStructure st = smimeInspect(raw);
    if (mimeMatch == "pkcs7-signature")
        return st.kind == QLatin1String("signed-detached") ? st.cms : QByteArray();
    if (st.kind == QLatin1String("encrypted") || st.kind == QLatin1String("signed-opaque"))
        return st.cms;
    return QByteArray();
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
    const QString outPath = smimeUniquePath(cacheDir, name);
    QFile f(outPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    const bool written = (f.write(decoded) == decoded.size()) && f.flush();
    f.close();
    // Listing an attachment that was not written hands the reader an empty or
    // truncated file under a trustworthy name.
    if (!written) { QFile::remove(outPath); return; }
    QVariantMap m;
    m[QStringLiteral("name")] = QFileInfo(outPath).fileName();
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
    // Random and neutral, like the PGP path — see mimeBoundary() in GpgEngine.cpp.
    const QByteArray bnd = "=_" + QUuid::createUuid().toRfc4122().toHex();
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
        // Only rewrite when the content actually differs — see writeIfChanged in
        // the OpenPGP engine for why an unconditional truncate is wrong here.
        const QByteArray want = "allow-loopback-pinentry\n"
                                "default-cache-ttl 0\n"
                                "max-cache-ttl 0\n"
                                "ignore-cache-for-signing\n"
                                "disable-scdaemon\n";
        QFile f(agentConf);
        QByteArray have;
        if (f.open(QIODevice::ReadOnly)) { have = f.readAll(); f.close(); }
        if (have != want && f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            f.write(want);
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

    // Scratch files of an interrupted run (a crash, a kill) may hold plaintext
    // of the last decrypted message — remove them before doing anything else.
    cleanupTempFiles();
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
    // No revocation checks — a considered trade, not an oversight. Trust is
    // anchored in the local store, not in a PKI (see trustRoot()), and
    // gpgsm's CRL path is hard-fail through a directory daemon the bundled
    // stack does not ship: mail has to stay readable offline.
    full << QStringLiteral("--homedir") << m_home
         << QStringLiteral("--batch")
         << QStringLiteral("--disable-crl-checks")
         << QStringLiteral("--agent-program") << m_agent
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
                             QByteArray *out, QByteArray *err, int timeoutMs,
                             const QString &passEnv)
{
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    // Our bundled openssl finds its legacy provider here (still links the SYSTEM
    // libssl/libcrypto). Do NOT add our gpg lib dir — openssl must use system libs.
    env.insert(QStringLiteral("OPENSSL_MODULES"), m_stack + QStringLiteral("/lib/ossl-modules"));
    // Passphrase via the child's environment (env:SFMAIL_PASS), never via argv:
    // /proc/<pid>/cmdline is readable by EVERY process, /proc/<pid>/environ only
    // by the same user and root.
    if (!passEnv.isEmpty())
        env.insert(QStringLiteral("SFMAIL_PASS"), passEnv);
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

QByteArray SmimeEngine::httpGet(const QString &url, int timeoutMs, int maxBytes)
{
    // https only: a certificate is being fetched to complete a trust chain — a
    // cleartext download could be swapped on the way. Capped: the URL comes out
    // of a certificate somebody else wrote.
    const QUrl u(url);
    if (u.scheme().toLower() != QLatin1String("https")) {
        log(QStringLiteral("AIA: refusing non-https issuer URL"));
        return QByteArray();
    }
    if (!m_nam) m_nam = new QNetworkAccessManager(this);
    QNetworkRequest req(u);
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    QNetworkReply *rep = m_nam->get(req);
    QEventLoop loop;
    QTimer t; t.setSingleShot(true);
    connect(&t, &QTimer::timeout, &loop, &QEventLoop::quit);
    connect(rep, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    connect(rep, &QNetworkReply::downloadProgress, &loop, [rep, maxBytes](qint64 got, qint64) {
        if (got > maxBytes) rep->abort();
    });
    t.start(timeoutMs);
    loop.exec();
    QByteArray data;
    if (rep->isFinished() && rep->error() == QNetworkReply::NoError
        && rep->url().scheme().toLower() == QLatin1String("https")) {
        data = rep->readAll();
        if (data.size() > maxBytes) data.clear();
    } else {
        rep->abort();
    }
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
    if (m_aiaRunning) return;              // httpGet spins an event loop: no re-entry
    m_aiaRunning = true;
    int fetched = 0;
    for (int guard = 0; guard < 12; ++guard) {
        const QVariantList certs = listCerts();
        QSet<QString> have;
        for (const QVariant &v : certs) have.insert(v.toMap().value(QStringLiteral("fpr")).toString());

        QString url;
        for (const QVariant &v : certs) {
            const QVariantMap m = v.toMap();
            if (m.value(QStringLiteral("isRoot")).toBool()) continue;
            const QString issuer = m.value(QStringLiteral("chainId")).toString();
            if (issuer.isEmpty() || have.contains(issuer)) continue;   // issuer already present
            const QString u = aiaCaIssuers(m.value(QStringLiteral("fpr")).toString());
            if (!u.isEmpty()) { url = u; break; }
        }
        if (url.isEmpty()) break;   // chain complete (or no AIA pointer to follow)

        log(QStringLiteral("AIA: fetching issuer certificate…"));
        const QByteArray certData = httpGet(url, 20000, 256 * 1024);
        if (certData.isEmpty()) { log(QStringLiteral("AIA: download failed")); break; }
        QByteArray io, ie;
        const bool ok = runGpgsm(QStringList() << QStringLiteral("--import"), certData, &io, &ie);
        invalidateCerts();
        if (!ok) { log(QStringLiteral("AIA: import of fetched issuer failed")); break; }
        ++fetched;
    }
    if (fetched) log(QStringLiteral("AIA: %1 issuer cert(s) added (not trusted)").arg(fetched));
    m_aiaRunning = false;
}

// The trust model, in one sentence: the local store IS the anchor. This app
// exists to exchange encrypted mail with closed PKI worlds without carrying a
// PKI of its own — whoever creates a certificate for themselves must be able to
// trust themselves when using it. Certificates are therefore treated like PGP
// keys: shown to the user and imported on their say-so. A ROOT becomes an
// anchor (trustlist.txt, "S relax" = trusted S/MIME root, lenient extension
// checks) only when the user confirms it in the import dialog, or when it is
// part of the user's OWN identity (.p12 import, self-signed generation).
QStringList SmimeEngine::trustedRoots() const
{
    QStringList out;
    QFile tl(m_home + QStringLiteral("/trustlist.txt"));
    if (!tl.open(QIODevice::ReadOnly | QIODevice::Text)) return out;
    for (const QByteArray &lr : tl.readAll().split('\n')) {
        const QString line = QString::fromUtf8(lr).trimmed();
        if (line.isEmpty() || line.startsWith('#') || line.startsWith('!')) continue;
        out << line.section(' ', 0, 0).toUpper();
    }
    return out;
}

void SmimeEngine::trustRoot(const QString &fpr)
{
    const QString f = fpr.trimmed().toUpper();
    if (f.isEmpty() || trustedRoots().contains(f)) return;
    QFile tl(m_home + QStringLiteral("/trustlist.txt"));
    if (!tl.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) return;
    tl.write(f.toUtf8() + " S relax\n");
    tl.close();
    log(QStringLiteral("trustlist: root %1 is now an anchor").arg(f.right(16)));
    // gpg-agent keeps the list in memory: tell it to re-read.
    QByteArray o, e;
    runGpgsm(QStringList() << QStringLiteral("--list-keys") << QStringLiteral("--with-colons"), QByteArray(), &o, &e, 15000);
    invalidateCerts();
}

void SmimeEngine::untrustRoot(const QString &fpr)
{
    const QString f = fpr.trimmed().toUpper();
    QFile tl(m_home + QStringLiteral("/trustlist.txt"));
    if (f.isEmpty() || !tl.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    const QList<QByteArray> lines = tl.readAll().split('\n');
    tl.close();
    QByteArray out; bool changed = false;
    for (const QByteArray &lr : lines) {
        if (QString::fromUtf8(lr).trimmed().section(' ', 0, 0).toUpper() == f) { changed = true; continue; }
        if (!lr.isEmpty()) out += lr + "\n";
    }
    if (!changed) return;
    if (tl.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) { tl.write(out); tl.close(); }
    invalidateCerts();
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
        // The fresh private key goes to STDOUT (captured in memory below) and is
        // then piped straight into the pkcs12 -export — it never touches disk
        // unencrypted. The cert goes to a file (public, harmless).
        << QStringLiteral("-keyout") << QStringLiteral("/proc/self/fd/1")
        << QStringLiteral("-out")    << certFile
        << QStringLiteral("-days")   << QString::number(days)
        << QStringLiteral("-nodes")          // unencrypted PEM (in memory); the p12 protects it
        << QStringLiteral("-sha256")
        << QStringLiteral("-subj")   << subj
        << QStringLiteral("-addext") << QStringLiteral("basicConstraints=critical,CA:FALSE")
        << QStringLiteral("-addext") << QStringLiteral("keyUsage=critical,digitalSignature,keyEncipherment")
        << QStringLiteral("-addext") << QStringLiteral("extendedKeyUsage=emailProtection")
        << QStringLiteral("-addext") << (QStringLiteral("subjectAltName=email:") + mail);
    QByteArray keyPem, re;
    if (!runOpenssl(req, QByteArray(), &keyPem, &re, 180000)
            || !keyPem.contains("PRIVATE KEY")) {
        keyPem.fill(0);
        emit importFinished(false, 0, QStringLiteral("openssl could not create the key/cert: %1")
                            .arg(QString::fromUtf8(re).trimmed()));
        return;
    }

    // Pack key+cert into a p12 protected by the user's passphrase, then reuse the
    // proven importP12() path (repack → gpgsm import → trust the self-signed root).
    // Key via stdin, passphrase via the environment — neither on disk nor on argv.
    QStringList exp;
    exp << QStringLiteral("pkcs12") << QStringLiteral("-export")
        << QStringLiteral("-inkey") << QStringLiteral("/proc/self/fd/0")
        << QStringLiteral("-in")    << certFile
        << QStringLiteral("-passout") << QStringLiteral("env:SFMAIL_PASS")
        << QStringLiteral("-out")   << p12File;
    QByteArray eo, ee;
    const bool packed = runOpenssl(exp, keyPem, &eo, &ee, 60000, passphrase);
    keyPem.fill(0);
    if (!packed) {
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

    // 1) Dump EVERYTHING (all certs + all private keys, unencrypted) from the .p12
    //    — to STDOUT, captured in memory. The unencrypted keys never touch the
    //    filesystem, and the passphrase travels via the environment, not argv
    //    (/proc/<pid>/cmdline is world-readable). Real-world .p12 files often
    //    use legacy algorithms → -legacy on OpenSSL 3.x; without it on 1.1.x.
    // Nothing else needs this child's stdin, so the passphrase goes there rather
    // than into its environment: /proc/<pid>/environ is readable by every process
    // of the same user, a pipe is not.
    QByteArray passIn = passphrase.toUtf8() + "\n";
    QStringList dump;
    dump << QStringLiteral("pkcs12") << QStringLiteral("-in") << path
         << QStringLiteral("-nodes")
         << QStringLiteral("-passin") << QStringLiteral("fd:0");
    if (legacy) dump << QStringLiteral("-legacy");
    QByteArray all, oerr;
    if (!runOpenssl(dump, passIn, &all, &oerr, 60000)) {
        // Retry once with the opposite -legacy choice (covers version surprises).
        QStringList dump2 = dump;
        if (legacy) dump2.removeAll(QStringLiteral("-legacy")); else dump2 << QStringLiteral("-legacy");
        if (!runOpenssl(dump2, passIn, &all, &oerr, 60000)) {
            passIn.fill(0);
            emit importFinished(false, 0, QStringLiteral("openssl could not read the .p12: %1")
                                .arg(QString::fromUtf8(oerr).trimmed()));
            return;
        }
    }
    passIn.fill(0);

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
        const QString certFile = wd + QStringLiteral("/cert%1.pem").arg(ki);
        const QString p12File  = wd + QStringLiteral("/key%1.p12").arg(ki);
        { QFile f(certFile); if (f.open(QIODevice::WriteOnly)) { f.write(certs[ci]); f.close(); } }

        // The unencrypted key goes to openssl via stdin (-inkey /proc/self/fd/0),
        // never as a file; the new p12's passphrase via the environment, not argv.
        QStringList exp;
        exp << QStringLiteral("pkcs12") << QStringLiteral("-export")
            << QStringLiteral("-inkey") << QStringLiteral("/proc/self/fd/0")
            << QStringLiteral("-in") << certFile;
        if (!chainPem.isEmpty()) exp << QStringLiteral("-certfile") << chainFile;
        exp << QStringLiteral("-passout") << QStringLiteral("env:SFMAIL_PASS")
            << QStringLiteral("-out") << p12File;
        QByteArray eo, ee;
        if (!runOpenssl(exp, keys[ki], &eo, &ee, 60000, passphrase)) {
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

    invalidateCerts();
    // 5) This is the user's OWN identity: the self-signed root(s) that came with
    //    it become trust anchors — that is what "importing my certificate" means.
    //    Nothing is fetched from the network here.
    {
        QByteArray own;
        for (const QByteArray &c : certs) own += c;
        const QVariantMap d = describeCertsPem(own, QString());
        for (const QVariant &v : d.value(QStringLiteral("certs")).toList()) {
            const QVariantMap cm = v.toMap();
            if (cm.value(QStringLiteral("selfSigned")).toBool())
                trustRoot(cm.value(QStringLiteral("fpr")).toString());
        }
    }

    emit certsChanged();
    if (imported > 0) emit importFinished(true, imported, QString());
    else emit importFinished(false, 0, QStringLiteral("no private key could be imported — check passphrase / see debug.log"));
}

// ---------------------------------------------------------------------------

// --- working directly on a received QMF message ----------------------------

QString SmimeEngine::messageKind(int messageId)
{
    const QString k = smimeInspect(smimeRawMessage(messageId)).kind;
    if (k == QLatin1String("encrypted")) return k;
    if (k.startsWith(QLatin1String("signed"))) return QStringLiteral("signed");
    return QString();
}

// --- signature verification ------------------------------------------------

static QString smimeStatusValue(const QByteArray &err, const char *tag)
{
    // "[GNUPG:] TAG rest" → rest (first occurrence)
    const QByteArray key = QByteArray("[GNUPG:] ") + tag;
    for (const QByteArray &lr : err.split('\n')) {
        const QByteArray l = lr.trimmed();
        if (l.startsWith(key) && (l.size() == key.size() || l.at(key.size()) == ' '))
            return QString::fromUtf8(l.mid(key.size()).trimmed());
    }
    return QString();
}
static bool smimeHasStatus(const QByteArray &err, const char *tag)
{
    const QByteArray key = QByteArray("[GNUPG:] ") + tag;
    for (const QByteArray &lr : err.split('\n')) {
        const QByteArray l = lr.trimmed();
        if (l.startsWith(key) && (l.size() == key.size() || l.at(key.size()) == ' ')) return true;
    }
    return false;
}
// stderr without the machine-readable status lines (for error texts).
static QString smimeHumanErr(const QByteArray &err)
{
    QStringList out;
    for (const QByteArray &lr : err.split('\n')) {
        const QString l = QString::fromUtf8(lr).trimmed();
        if (l.isEmpty() || l.startsWith(QStringLiteral("[GNUPG:]"))) continue;
        out << l;
    }
    return out.join(QStringLiteral("\n"));
}

QVariantMap SmimeEngine::verifyRaw(const QByteArray &raw, QByteArray *contentOut)
{
    QVariantMap r;
    r[QStringLiteral("status")] = QStringLiteral("none");
    r[QStringLiteral("trust")] = QString();
    r[QStringLiteral("fpr")] = QString();
    r[QStringLiteral("subject")] = QString();
    r[QStringLiteral("emails")] = QStringList();
    r[QStringLiteral("certInStore")] = false;
    r[QStringLiteral("note")] = QString();
    r[QStringLiteral("error")] = QString();
    if (contentOut) contentOut->clear();
    if (!m_available) { r[QStringLiteral("status")] = QStringLiteral("error"); r[QStringLiteral("error")] = QStringLiteral("gpgsm not available"); return r; }

    const SmimeStructure st = smimeInspect(raw);
    if (!st.kind.startsWith(QLatin1String("signed")) || st.cms.isEmpty()) return r;

    // gpgsm stores every certificate it finds in a signed message in the keybox
    // as a side effect of verifying. That would turn any sender's certificate
    // into an encryption candidate without the user ever seeing it — so
    // snapshot the store first and remove what the verification added.
    QSet<QString> before;
    for (const QVariant &v : listCerts()) before.insert(v.toMap().value(QStringLiteral("fpr")).toString().toUpper());

    QStringList args;
    args << QStringLiteral("--status-fd") << QStringLiteral("2");
    QByteArray out, err;
    bool okRun = false;
    if (st.kind == QLatin1String("signed-opaque")) {
        // The CMS goes in on stdin, the verified payload comes out on stdout.
        args << QStringLiteral("--output") << QStringLiteral("/proc/self/fd/1") << QStringLiteral("--verify");
        okRun = runGpgsm(args, st.cms, &out, &err, 60000);
    } else {
        // Detached: the signature on stdin, the signed bytes from a scratch file
        // in our private home (public data — this is an unencrypted signed part).
        QTemporaryDir td(m_home + QStringLiteral("/verify-XXXXXX"));
        if (!td.isValid()) { r[QStringLiteral("status")] = QStringLiteral("error"); r[QStringLiteral("error")] = QStringLiteral("no temp dir"); return r; }
        const QString cf = td.path() + QStringLiteral("/content");
        auto tryContent = [&](const QByteArray &content) -> bool {
            QFile f(cf);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
            f.write(content); f.close();
            QStringList a = args;
            a << QStringLiteral("--verify") << QStringLiteral("/proc/self/fd/0") << cf;
            out.clear(); err.clear();
            return runGpgsm(a, st.cms, &out, &err, 60000);
        };
        okRun = tryContent(st.signedContent);
        if (smimeHasStatus(err, "BADSIG") && st.signedContent.contains('\n')
            && !st.signedContent.contains("\r\n")) {
            // Stored with bare LF although it was signed as CRLF (canonical form).
            QByteArray crlf = st.signedContent; crlf.replace("\n", "\r\n");
            okRun = tryContent(crlf);
        }
        out = st.signedContent;
    }
    Q_UNUSED(okRun);

    const QString good = smimeStatusValue(err, "GOODSIG");
    const QString bad  = smimeStatusValue(err, "BADSIG");
    QString fpr = (!good.isEmpty() ? good : bad).section(' ', 0, 0).toUpper();
    r[QStringLiteral("fpr")] = fpr;
    if (!good.isEmpty()) {
        const bool trusted = smimeHasStatus(err, "TRUST_FULLY") || smimeHasStatus(err, "TRUST_ULTIMATE");
        r[QStringLiteral("trust")] = trusted ? QStringLiteral("full")
                                   : smimeHasStatus(err, "TRUST_NEVER") ? QStringLiteral("never")
                                   : smimeHasStatus(err, "TRUST_MARGINAL") ? QStringLiteral("marginal")
                                                                            : QStringLiteral("undefined");
        r[QStringLiteral("status")] = trusted ? QStringLiteral("good") : QStringLiteral("good-untrusted");
        if (contentOut) *contentOut = out;
    } else if (!bad.isEmpty()) {
        r[QStringLiteral("status")] = QStringLiteral("bad");
        if (contentOut) *contentOut = out;    // the reader may still see it — flagged red
    } else if (smimeHasStatus(err, "ERRSIG") || err.contains("verify.findkey")
               || err.contains("No public key") || err.contains("certificate not found")) {
        r[QStringLiteral("status")] = QStringLiteral("nocert");
        r[QStringLiteral("error")] = smimeHumanErr(err);
    } else {
        r[QStringLiteral("status")] = QStringLiteral("error");
        r[QStringLiteral("error")] = smimeHumanErr(err);
    }

    // Signer details while its certificate is still in the keybox.
    if (!fpr.isEmpty()) {
        QByteArray lo, le;
        runGpgsm(QStringList() << QStringLiteral("--with-colons") << QStringLiteral("--list-keys") << fpr,
                 QByteArray(), &lo, &le, 30000);
        QStringList emails; QString subject;
        for (const QByteArray &lr : lo.split('\n')) {
            const QStringList f = QString::fromUtf8(lr).split(':');
            if (f.isEmpty() || f[0] != QLatin1String("uid")) continue;
            const QString u = f.value(9).trimmed();
            if (u.startsWith('<') && u.endsWith('>')) {
                const QString e = u.mid(1, u.size() - 2).toLower();
                if (!e.isEmpty() && !emails.contains(e)) emails << e;
            } else if (subject.isEmpty()) {
                subject = u;
            }
        }
        r[QStringLiteral("emails")] = emails;
        r[QStringLiteral("subject")] = subject;
        r[QStringLiteral("certInStore")] = before.contains(fpr);
    }

    // Undo gpgsm's silent storing of the message's certificates.
    invalidateCerts();
    for (const QVariant &v : listCerts()) {
        const QString f = v.toMap().value(QStringLiteral("fpr")).toString().toUpper();
        if (before.contains(f)) continue;
        QByteArray o, e;
        runGpgsm(QStringList() << QStringLiteral("--yes") << QStringLiteral("--delete-keys") << f, QByteArray(), &o, &e, 30000);
    }
    invalidateCerts();

    const QString stt = r.value(QStringLiteral("status")).toString();
    const QString who = !r.value(QStringLiteral("emails")).toStringList().isEmpty()
                        ? r.value(QStringLiteral("emails")).toStringList().first()
                        : r.value(QStringLiteral("subject")).toString();
    if (stt == QLatin1String("good"))
        r[QStringLiteral("note")] = QStringLiteral("Valid S/MIME signature from %1").arg(who);
    else if (stt == QLatin1String("good-untrusted"))
        r[QStringLiteral("note")] = QStringLiteral("Signature valid (%1), but its certificate chain is not trusted by your store").arg(who);
    else if (stt == QLatin1String("bad"))
        r[QStringLiteral("note")] = QStringLiteral("⚠ INVALID S/MIME signature — the message was altered or the signature is forged");
    else if (stt == QLatin1String("nocert"))
        r[QStringLiteral("note")] = QStringLiteral("Signed, but the signer's certificate is not available — cannot verify");
    else if (stt == QLatin1String("error"))
        r[QStringLiteral("note")] = QStringLiteral("Signature could not be verified");
    log(QStringLiteral("verify: %1 (trust %2)").arg(stt, r.value(QStringLiteral("trust")).toString()));
    return r;
}

QVariantMap SmimeEngine::verifyMessage(int messageId)
{
    if (m_verifyCache.contains(messageId)) return m_verifyCache.value(messageId);
    QVariantMap r = verifyRaw(smimeRawMessage(messageId), nullptr);
    if (r.value(QStringLiteral("status")).toString() != QLatin1String("error"))
        m_verifyCache.insert(messageId, r);
    return r;
}

// --- confirmed import of other people's certificates -----------------------

QVariantMap SmimeEngine::describeCertsPem(const QByteArray &pem, const QString &senderEmail)
{
    QVariantMap res;
    QVariantList certs;
    const QList<QByteArray> blocks = pemBlocks(pem, "CERTIFICATE");
    const QVariantList store = listCerts();
    const QStringList roots = trustedRoots();
    QString sender = senderEmail.trimmed().toLower();
    const int lt = sender.indexOf('<');
    if (lt >= 0) { const int gt = sender.indexOf('>', lt + 1); if (gt > lt) sender = sender.mid(lt + 1, gt - lt - 1).trimmed(); }
    bool senderMatches = false, anyRoot = false, allRootsTrusted = true;
    for (const QByteArray &c : blocks) {
        QByteArray o, e;
        runOpenssl(QStringList() << QStringLiteral("x509") << QStringLiteral("-noout")
                                 << QStringLiteral("-subject") << QStringLiteral("-issuer")
                                 << QStringLiteral("-fingerprint") << QStringLiteral("-sha1")
                                 << QStringLiteral("-dates") << QStringLiteral("-email")
                                 << QStringLiteral("-ext") << QStringLiteral("basicConstraints"),
                   c, &o, &e, 15000);
        QVariantMap m;
        QStringList emails; QString subject, issuer, fpr, nb, na; bool ca = false;
        for (const QByteArray &lr : o.split('\n')) {
            const QString l = QString::fromUtf8(lr).trimmed();
            if (l.startsWith(QStringLiteral("subject="))) subject = l.mid(8).trimmed();
            else if (l.startsWith(QStringLiteral("issuer="))) issuer = l.mid(7).trimmed();
            else if (l.contains(QStringLiteral("Fingerprint="))) { fpr = l.section('=', 1).trimmed(); fpr.remove(':'); fpr = fpr.toUpper(); }
            else if (l.startsWith(QStringLiteral("notBefore="))) nb = l.mid(10).trimmed();
            else if (l.startsWith(QStringLiteral("notAfter="))) na = l.mid(9).trimmed();
            else if (l.contains(QStringLiteral("CA:TRUE"))) ca = true;
            else if (l.contains('@') && !l.contains('=') && !l.contains(' ')) { const QString em = l.toLower(); if (!emails.contains(em)) emails << em; }
        }
        if (fpr.isEmpty()) continue;
        // Expiry against the device clock (openssl prints "Sep  6 12:24:01 2026 GMT").
        bool expired = false;
        {
            QByteArray eo, ee;
            runOpenssl(QStringList() << QStringLiteral("x509") << QStringLiteral("-noout")
                                     << QStringLiteral("-checkend") << QStringLiteral("0"), c, &eo, &ee, 15000);
            expired = eo.contains("will expire");
        }
        const bool selfSigned = !subject.isEmpty() && subject == issuer;
        bool inStore = false;
        QVariantList conflicts;
        for (const QVariant &v : store) {
            const QVariantMap sm = v.toMap();
            const QString sf = sm.value(QStringLiteral("fpr")).toString().toUpper();
            if (sf == fpr) { inStore = true; continue; }
            if (ca || sm.value(QStringLiteral("isCA")).toBool()) continue;
            const QStringList se = sm.value(QStringLiteral("emails")).toStringList();
            bool shares = false;
            for (const QString &em : emails) if (se.contains(em)) { shares = true; break; }
            if (shares) {
                QVariantMap cm;
                cm[QStringLiteral("fpr")] = sf;
                cm[QStringLiteral("subject")] = sm.value(QStringLiteral("uid"));
                conflicts << cm;
            }
        }
        if (!ca && !sender.isEmpty() && emails.contains(sender)) senderMatches = true;
        if (selfSigned) { anyRoot = true; if (!roots.contains(fpr)) allRootsTrusted = false; }
        m[QStringLiteral("subject")] = subject;
        m[QStringLiteral("issuer")] = issuer;
        m[QStringLiteral("emails")] = emails;
        m[QStringLiteral("fpr")] = fpr;
        m[QStringLiteral("notBefore")] = nb;
        m[QStringLiteral("notAfter")] = na;
        m[QStringLiteral("expired")] = expired;
        m[QStringLiteral("isCA")] = ca || selfSigned;
        m[QStringLiteral("selfSigned")] = selfSigned;
        m[QStringLiteral("inStore")] = inStore;
        m[QStringLiteral("conflicts")] = conflicts;
        certs << m;
    }
    res[QStringLiteral("certs")] = certs;
    res[QStringLiteral("count")] = certs.size();
    res[QStringLiteral("senderEmail")] = sender;
    res[QStringLiteral("senderKnown")] = !sender.isEmpty();
    res[QStringLiteral("senderMatches")] = senderMatches;
    res[QStringLiteral("hasRoot")] = anyRoot;
    res[QStringLiteral("rootsTrusted")] = anyRoot && allRootsTrusted;
    return res;
}

QVariantMap SmimeEngine::inspectCertImport(const QString &source, const QString &arg,
                                           const QString &senderEmail)
{
    m_inspectPem.clear(); m_inspectInfo.clear();
    QVariantMap none; none[QStringLiteral("count")] = 0;
    if (!m_available) { none[QStringLiteral("error")] = QStringLiteral("gpgsm not available"); return none; }
    QByteArray pem;
    if (source == QLatin1String("pending")) {
        pem = m_pendingSenderCertPem;
    } else if (source == QLatin1String("message")) {
        pem = senderCertPemOf(arg.toInt());
    } else {
        QString p = arg;
        if (p.startsWith(QStringLiteral("file://"))) p = p.mid(7);
        QByteArray data;
        if (QFileInfo::exists(p)) { QFile f(p); if (f.open(QIODevice::ReadOnly)) { data = f.read(8 * 1024 * 1024); f.close(); } }
        if (data.isEmpty()) { none[QStringLiteral("error")] = QStringLiteral("empty input"); return none; }
        if (data.contains("-----BEGIN CERTIFICATE-----")) {
            pem = data;
        } else if (data.contains("-----BEGIN PKCS7-----")) {
            QByteArray o, e;
            runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-print_certs"), data, &o, &e, 20000);
            pem = o;
        } else if (!smimeInspect(data).kind.isEmpty()) {
            const SmimeStructure st = smimeInspect(data);
            QByteArray o, e;
            runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform") << QStringLiteral("DER")
                                     << QStringLiteral("-print_certs"), st.cms, &o, &e, 20000);
            pem = o;
        } else {
            // DER: a single certificate or a PKCS#7 bundle.
            QByteArray o, e;
            runOpenssl(QStringList() << QStringLiteral("x509") << QStringLiteral("-inform") << QStringLiteral("DER"), data, &o, &e, 20000);
            if (o.isEmpty())
                runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform") << QStringLiteral("DER")
                                         << QStringLiteral("-print_certs"), data, &o, &e, 20000);
            pem = o;
        }
    }
    if (pem.isEmpty()) { none[QStringLiteral("error")] = QStringLiteral("no certificate found"); return none; }
    QVariantMap info = describeCertsPem(pem, senderEmail);
    if (info.value(QStringLiteral("count")).toInt() == 0) { none[QStringLiteral("error")] = QStringLiteral("no readable certificate"); return none; }
    m_inspectPem = pem;
    m_inspectInfo = info;
    return info;
}

void SmimeEngine::importInspected(bool trustRoots, bool fetchAia)
{
    if (!m_available) { emit importFinished(false, 0, QStringLiteral("gpgsm not available")); return; }
    if (m_inspectPem.isEmpty()) { emit importFinished(false, 0, QStringLiteral("nothing inspected to import")); return; }
    QByteArray io, ie;
    const bool ok = runGpgsm(QStringList() << QStringLiteral("--import"), m_inspectPem, &io, &ie);
    invalidateCerts();
    log(QStringLiteral("cert import: %1").arg(smimeHumanErr(ie)));
    int n = 0;
    {
        // IMPORT_RES <count> <imported> <unchanged> ... on the status line would
        // be cleaner; gpgsm --import prints its summary on stderr in English
        // (the bundle ships no locales).
        const QString es = QString::fromUtf8(ie);
        const int idx = es.indexOf(QStringLiteral("imported:"));
        if (idx >= 0) n = es.mid(idx + 9).trimmed().section('\n', 0, 0).trimmed().toInt();
    }
    if (trustRoots) {
        for (const QVariant &v : m_inspectInfo.value(QStringLiteral("certs")).toList()) {
            const QVariantMap cm = v.toMap();
            if (cm.value(QStringLiteral("selfSigned")).toBool())
                trustRoot(cm.value(QStringLiteral("fpr")).toString());
        }
    }
    if (fetchAia) completeChainViaAia();
    m_inspectPem.clear(); m_inspectInfo.clear();
    emit certsChanged();
    if (ok) emit importFinished(true, n, QString());
    else    emit importFinished(false, 0, smimeHumanErr(ie));
}

void SmimeEngine::decryptMessage(int messageId, const QString &passphrase)
{
    const QVariantMap noSig;
    if (!m_available) { emit decryptFinished(false, QString(), QString(), QStringLiteral("gpgsm not available"), noSig, messageId); return; }
    const QByteArray raw = smimeRawMessage(messageId);
    if (raw.isEmpty()) { emit decryptFinished(false, QString(), QString(), QStringLiteral("message not downloaded yet"), noSig, messageId); return; }
    const SmimeStructure st = smimeInspect(raw);
    if (st.kind != QLatin1String("encrypted") || st.cms.isEmpty()) {
        emit decryptFinished(false, QString(), QString(), QStringLiteral("no encrypted S/MIME part found"), noSig, messageId); return;
    }

    QByteArray inner, err;
    QByteArray pass = passphrase.toUtf8() + "\n";
    runGpgsm(QStringList() << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                           << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
                           << QStringLiteral("--status-fd") << QStringLiteral("2")
                           << QStringLiteral("--decrypt"),
             pass + st.cms, &inner, &err, 90000);
    pass.fill(0);
    // Judge by the status line, not the exit code: gpgsm exits non-zero when ANY
    // recipient's key is missing — e.g. the encrypt-to-self copy is also
    // encrypted to the other party — although OUR key decrypted it fine.
    if (!smimeHasStatus(err, "DECRYPTION_OKAY") || inner.isEmpty()) {
        emit decryptFinished(false, QString(), QString(), smimeHumanErr(err), noSig, messageId); return;
    }

    // The decrypted content may be plain MIME, multipart/signed, or an OPAQUE
    // signed-data CMS that encapsulates the real content. Signed layers are
    // verified with gpgsm and unwrapped; the reader sees the payload with the
    // verification result next to it.
    QByteArray content = inner;
    QByteArray certDer;
    QVariantMap sig;
    const SmimeStructure in = smimeInspect(inner);
    if (in.kind.startsWith(QLatin1String("signed"))) {
        certDer = in.cms;   // signer certs live in this CMS
        QByteArray verified;
        sig = verifyRaw(inner, &verified);
        if (!verified.isEmpty()) content = verified;
        else if (in.kind == QLatin1String("signed-opaque")) {
            // Not verifiable (no certificate, gpgsm error): still show the text,
            // clearly flagged — a mail the user cannot read helps nobody.
            QByteArray vout, verr;
            runOpenssl(QStringList() << QStringLiteral("smime") << QStringLiteral("-verify")
                                     << QStringLiteral("-noverify") << QStringLiteral("-inform")
                                     << QStringLiteral("DER") << QStringLiteral("-in") << QStringLiteral("/proc/self/fd/0"),
                       in.cms, &vout, &verr, 20000);
            if (!vout.isEmpty()) content = vout;
        } else {
            content = in.signedContent;
        }
    }

    // Stash the sender cert(s) for an explicit, confirmed import (never automatic).
    m_pendingSenderCertPem.clear();
    if (!certDer.isEmpty()) {
        QByteArray pem, e1;
        runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform")
                                 << QStringLiteral("DER") << QStringLiteral("-print_certs"),
                   certDer, &pem, &e1, 20000);
        if (!pem.isEmpty()) m_pendingSenderCertPem = pem;
    }
    QString signer;
    if (!m_pendingSenderCertPem.isEmpty())
        signer = certsAllInStore(m_pendingSenderCertPem) ? QStringLiteral("cert-present")
                                                         : QStringLiteral("cert-new");
    m_lastDecMsgId = messageId;
    m_lastDecSignerPem = m_pendingSenderCertPem;
    m_lastDecAttachments = smimeExtractAttachments(content, QString());   // in-memory, no part files
    emit decryptFinished(true, smimeReadableText(content), signer, QString(), sig, messageId);
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
    const SmimeStructure st = smimeInspect(raw);
    if (!st.kind.startsWith(QLatin1String("signed")) || st.cms.isEmpty()) return QByteArray();
    QByteArray pem, e;
    runOpenssl(QStringList() << QStringLiteral("pkcs7") << QStringLiteral("-inform")
                             << QStringLiteral("DER") << QStringLiteral("-print_certs"),
               st.cms, &pem, &e, 20000);
    return pem;
}

bool SmimeEngine::senderCertMissing(int messageId)
{
    if (!m_available) return false;
    const QByteArray pem = senderCertPemOf(messageId);
    if (pem.isEmpty()) return false;           // encrypted (cert is inside) or none
    return !certsAllInStore(pem);
}

void SmimeEngine::invalidateCerts()
{
    m_certCacheValid = false;
    m_certCache.clear();
    m_verifyCache.clear();
}

void SmimeEngine::cleanupTempFiles()
{
    QDir d(m_home);
    QFile::remove(m_home + QStringLiteral("/tmp_sd.der"));
    const QStringList pats = QStringList() << QStringLiteral("gen-*") << QStringLiteral("import-*")
                                           << QStringLiteral("sign-*") << QStringLiteral("send-*")
                                           << QStringLiteral("verify-*");
    for (const QString &sub : d.entryList(pats, QDir::Dirs | QDir::NoDotAndDotDot))
        QDir(m_home + QStringLiteral("/") + sub).removeRecursively();
}

QVariantList SmimeEngine::listCerts()
{
    if (m_certCacheValid) return m_certCache;
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
            // Colon format: 6 = creation, 7 = expiry (seconds since epoch or ISO).
            // Needed to prefer the NEWEST certificate when several match.
            cur[QStringLiteral("created")] = f.value(5);
            cur[QStringLiteral("expires")] = f.value(6);
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
            // Prefer an e-mail-looking UID over the raw DN; collect EVERY address
            // ("<addr>" records) so callers can match exactly, never by substring.
            const QString u = f.value(9).trimmed();
            if (u.contains('@') || !cur.contains(QStringLiteral("uid"))) cur[QStringLiteral("uid")] = u;
            QStringList emails = cur.value(QStringLiteral("emails")).toStringList();
            if (u.startsWith('<') && u.endsWith('>')) {
                const QString e = u.mid(1, u.size() - 2).toLower();
                if (!e.isEmpty() && !emails.contains(e)) emails << e;
            }
            cur[QStringLiteral("emails")] = emails;
        }
    }
    if (!cur.isEmpty()) res.append(cur);
    m_certCache = res;
    m_certCacheValid = true;
    return res;
}

// Exact address match against the certificate's subjectAltName addresses.
static bool certHasEmail(const QVariantMap &cert, const QString &email)
{
    if (email.isEmpty()) return true;
    const QString want = email.trimmed().toLower();
    return cert.value(QStringLiteral("emails")).toStringList().contains(want);
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
    untrustRoot(fingerprint);        // a deleted root is no anchor any more
    invalidateCerts();
    log(QStringLiteral("deleteCert %1: %2 %3").arg(fingerprint.right(16)).arg(ok ? "ok" : "FAIL")
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

// Where the "use THIS certificate" choice lives. Explicit INI path under the
// app's own data directory — the same pattern the signed-memory store uses, and
// the only one that survives the sandbox (a default-constructed QSettings writes
// one level above the app's directory, where Sailjail refuses silently).
QString SmimeEngine::prefStorePath() const
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/smime-preferred.ini");
}

// Remember which certificate to use for an address. Empty fingerprint clears it
// and returns to the automatic rule.
void SmimeEngine::setPreferredCert(const QString &email, const QString &fingerprint)
{
    if (email.isEmpty()) return;
    QSettings s(prefStorePath(), QSettings::IniFormat);
    const QString key = QStringLiteral("encrypt/") + email.toLower();
    if (fingerprint.isEmpty()) s.remove(key);
    else                       s.setValue(key, fingerprint);
    s.sync();
    if (s.status() != QSettings::NoError)
        qWarning() << "[smime] could not store the preferred certificate:" << s.status();
    emit preferredCertChanged(email, fingerprint);
}

QString SmimeEngine::preferredCert(const QString &email)
{
    if (email.isEmpty()) return QString();
    QSettings s(prefStorePath(), QSettings::IniFormat);
    return s.value(QStringLiteral("encrypt/") + email.toLower()).toString();
}

// gpgsm's colon output gives the creation date either as seconds since the epoch
// or as an ISO timestamp; normalise so certificates can be ordered by age.
static qint64 certCreated(const QVariantMap &m)
{
    const QString s = m.value(QStringLiteral("created")).toString();
    if (s.isEmpty()) return 0;
    bool ok = false;
    const qint64 secs = s.toLongLong(&ok);
    if (ok) return secs;
    const QDateTime dt = QDateTime::fromString(s.left(15), QStringLiteral("yyyyMMddTHHmmss"));
    return dt.isValid() ? dt.toMSecsSinceEpoch() / 1000 : 0;   // Qt 5.6: kein toSecsSinceEpoch
}

// Pick ONE certificate for an address instead of handing gpgsm the address and
// letting it choose. With several certificates on the same address gpgsm refuses
// outright ("can't encrypt to '…': Ambiguous name"), and where it does choose it
// may take one that cannot encrypt at all ("certificate is not usable for
// encryption") — both reproduced on the device with four certificates on the
// sender's own address. Rule: right key usage, not a CA, still valid, and of
// those the NEWEST. The newest is what a user who just created a certificate
// expects to be used; the old ones stay in the store for decrypting old mail.
QString SmimeEngine::pickCertFpr(const QString &email, char usage, bool needSecret)
{
    const QString want = (usage == 'e') ? QStringLiteral("e") : QStringLiteral("s");
    const qint64 now = QDateTime::currentMSecsSinceEpoch() / 1000;   // Qt 5.6

    // An explicit choice wins over any heuristic — but only while it still fits:
    // a certificate the user picked and then let expire must not silently break
    // sending, so it falls back to the automatic rule.
    const QString chosen = preferredCert(email);
    if (!chosen.isEmpty()) {
        for (const QVariant &v : listCerts()) {
            const QVariantMap m = v.toMap();
            if (m.value(QStringLiteral("fpr")).toString() != chosen) continue;
            if (!m.value(QStringLiteral("keyUsage")).toString().toLower().contains(want)) break;
            if (needSecret && !m.value(QStringLiteral("hasSecret")).toBool()) break;
            bool okExp = false;
            const qint64 exp = m.value(QStringLiteral("expires")).toString().toLongLong(&okExp);
            if (okExp && exp > 0 && exp < now) break;
            return chosen;
        }
        qWarning() << "[smime] preferred certificate no longer usable, falling back";
    }

    QString best;
    qint64 bestAge = -1;
    for (const QVariant &v : listCerts()) {
        const QVariantMap m = v.toMap();
        if (m.value(QStringLiteral("isCA")).toBool()) continue;
        if (needSecret && !m.value(QStringLiteral("hasSecret")).toBool()) continue;
        if (!m.value(QStringLiteral("keyUsage")).toString().toLower().contains(want)) continue;
        if (!certHasEmail(m, email)) continue;
        bool ok = false;
        const qint64 exp = m.value(QStringLiteral("expires")).toString().toLongLong(&ok);
        if (ok && exp > 0 && exp < now) continue;          // expired
        const qint64 age = certCreated(m);
        if (age >= bestAge) { bestAge = age; best = m.value(QStringLiteral("fpr")).toString(); }
    }
    return best;
}

QString SmimeEngine::ownCertFpr(const QString &email, char usage)
{
    const QString want = (usage == 'e') ? QStringLiteral("e") : QStringLiteral("s");
    const QVariantList certs = listCerts();
    // For SIGNING the cert must be valid for "emailProtection". Some CAs issue
    // THREE certs for the same address: a signing cert
    // (digitalSignature+nonRepudiation, EKU emailProtection), an encryption cert
    // (keyEncipherment, EKU emailProtection) and an AUTHENTICATION/login cert
    // (digitalSignature, EKU clientAuth ONLY). The auth cert also reports key usage
    // 's', so "first cert that can sign" picks it — and strict clients then reject
    // the signature ("certificate not valid for the selected purpose": EKU is
    // clientAuth, not emailProtection). Careful clients filter it out the same way
    // and never offer it. So we additionally require the EKU to permit emailProtection.
    const bool needEmail = (usage == 's');
    QString fallback;   // EKU-unrestricted match; used only if no emailProtection cert exists
    for (int pass = 0; pass < 2; ++pass) {   // pass 0: match the address; pass 1: any
        for (const QVariant &v : certs) {
            const QVariantMap m = v.toMap();
            if (!m.value(QStringLiteral("hasSecret")).toBool()) continue;
            if (!m.value(QStringLiteral("keyUsage")).toString().toLower().contains(want)) continue;
            if (pass == 0 && !certHasEmail(m, email)) continue;
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
    // Same rule as the choice at send time: a usable encryption certificate
    // whose subjectAltName carries exactly this address.
    if (!m_available || email.isEmpty()) return false;
    return !pickCertFpr(email.trimmed(), 'e', false).isEmpty();
}

QByteArray SmimeEngine::signWithChain(const QByteArray &inner, const QString &signFpr,
                                      const QString &fromAddr, const QString &passphrase,
                                      QByteArray *errOut)
{
    QByteArray dummy; QByteArray &err = errOut ? *errOut : dummy;
    QTemporaryDir td(m_home + QStringLiteral("/sign-XXXXXX"));
    if (!td.isValid()) { err = "no temp dir"; return QByteArray(); }
    const QString p12f    = td.path() + QStringLiteral("/sign.p12");
    const QString signerf = td.path() + QStringLiteral("/signer.pem");
    const QString certf   = td.path() + QStringLiteral("/extra.pem");
    const QString cf      = td.path() + QStringLiteral("/content");
    const QString sigf    = td.path() + QStringLiteral("/sig.der");

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

    // 2) PKCS#12 → key IN MEMORY (stdout capture) + signer cert on disk. The
    //    unencrypted private key never touches the filesystem: -nocerts sends it
    //    to stdout, and step 4 feeds it to cms via stdin. Only the (public)
    //    signer cert is written out. The p12 on disk stays passphrase-protected.
    //    gpgsm exports with legacy RC2, so OpenSSL 3.x needs -legacy to read it.
    //    The passphrase travels via the environment, never on the command line.
    QStringList ok_; ok_ << QStringLiteral("pkcs12") << QStringLiteral("-in") << p12f
                         << QStringLiteral("-nocerts") << QStringLiteral("-nodes");
    if (opensslHasLegacy()) ok_ << QStringLiteral("-legacy");
    ok_ << QStringLiteral("-passin") << QStringLiteral("env:SFMAIL_PASS");
    QByteArray keyPem, oe;
    if (!runOpenssl(ok_, QByteArray(), &keyPem, &oe, 30000, passphrase)
            || !keyPem.contains("PRIVATE KEY")) {
        err = (QStringLiteral("p12→key failed: ") + QString::fromUtf8(oe).trimmed()).toUtf8(); return QByteArray();
    }
    QStringList oc; oc << QStringLiteral("pkcs12") << QStringLiteral("-in") << p12f
                       << QStringLiteral("-nokeys");
    if (opensslHasLegacy()) oc << QStringLiteral("-legacy");
    oc << QStringLiteral("-passin") << QStringLiteral("env:SFMAIL_PASS")
       << QStringLiteral("-out") << signerf;
    QByteArray oo;
    if (!runOpenssl(oc, QByteArray(), &oo, &oe, 30000, passphrase) || !QFileInfo::exists(signerf)) {
        keyPem.fill(0);
        err = (QStringLiteral("p12→cert failed: ") + QString::fromUtf8(oe).trimmed()).toUtf8(); return QByteArray();
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
    if (extra.isEmpty()) { keyPem.fill(0); err = "no encryption cert / chain to embed"; return QByteArray(); }
    { QFile f(certf); if (f.open(QIODevice::WriteOnly)) f.write(extra); }
    { QFile f(cf);    if (f.open(QIODevice::WriteOnly)) f.write(inner); }

    // 4) Opaque CMS signature with openssl, embedding -certfile. -binary keeps the
    //    content byte-exact (no CRLF canonicalisation). The private key arrives on
    //    stdin (-inkey /proc/self/fd/0) straight from memory — verified to work
    //    with the bundled OpenSSL 3.5.6 on-device.
    QStringList s; s << QStringLiteral("cms") << QStringLiteral("-sign")
                     << QStringLiteral("-signer") << signerf
                     << QStringLiteral("-inkey") << QStringLiteral("/proc/self/fd/0")
                     << QStringLiteral("-certfile") << certf
                     << QStringLiteral("-nodetach") << QStringLiteral("-binary")
                     << QStringLiteral("-outform") << QStringLiteral("DER")
                     << QStringLiteral("-in") << cf << QStringLiteral("-out") << sigf;
    QByteArray so, se;
    const bool signedOk = runOpenssl(s, keyPem, &so, &se, 60000);
    keyPem.fill(0);   // the only unencrypted copy of the key — wipe it
    if (!signedOk || !QFileInfo::exists(sigf)) {
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
        // (so recipients' clients can reply encrypted).
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

    // 2) Optional encrypt → enveloped-data CMS.
    //
    // ONE MESSAGE PER AUDIENCE when there are blind copies. CMS puts a
    // RecipientInfo (issuer + serial of the certificate) into the envelope for
    // every recipient, so a single message encrypted to everyone hands each
    // recipient the list of all others — exactly what a blind copy must not do.
    // The signed content is built once above and reused; only the envelope
    // differs per audience. Without blind copies this is one message as before.
    struct Copy { QStringList to, cc, bcc; QByteArray body; };
    QList<Copy> copies;

    if (!encrypt) {
        // Sign-only: the pkcs7-mime signed-data IS the body. Nothing names the
        // recipients here, so blind copies can ride along in one message (QMF
        // strips the Bcc header on transmission and uses it for the envelope).
        Copy c; c.to = to; c.cc = cc; c.bcc = bcc; c.body = content;
        copies << c;
    } else {
        // Encrypting to an address list, once per audience.
        auto envelopeFor = [&](const QStringList &addresses, QByteArray *out) -> bool {
            QStringList args;
            for (const QString &r : addresses) {
                const QString addr = r.trimmed();
                if (addr.isEmpty()) continue;
                // Address me the certificate, not the address: gpgsm refuses to choose
                // when several certificates carry the same address. Fall back to the
                // address only when nothing matches, so the error stays gpgsm's.
                const QString fpr = pickCertFpr(addr, 'e', false);
                args << QStringLiteral("-r") << (fpr.isEmpty() ? addr : fpr);
            }
            if (args.isEmpty()) return false;
            args << QStringLiteral("--encrypt") << QStringLiteral("--output") << QStringLiteral("-");
            QByteArray env, eerr;
            if (!runGpgsm(args, content, &env, &eerr, 90000) || env.isEmpty()) {
                emit sendFinished(false, QStringLiteral("Encryption failed (recipient certificate missing or untrusted?): %1")
                                  .arg(QString::fromUtf8(eerr).trimmed()));
                return false;
            }
            *out = pkcs7MimeEntity(env, "enveloped-data");
            return true;
        };

        if (!to.isEmpty() || !cc.isEmpty()) {
            QStringList open = to; open += cc;
            if (!fromAddr.isEmpty()) open << fromAddr;   // encrypt-to-self for a readable Sent copy
            Copy c; c.to = to; c.cc = cc;                // no Bcc header on the open copy
            if (!envelopeFor(open, &c.body)) return;
            copies << c;
        }
        for (const QString &b : bcc) {
            const QString addr = b.trimmed();
            if (addr.isEmpty()) continue;
            QStringList one; one << addr;
            if (!fromAddr.isEmpty()) one << fromAddr;
            // Addressed to its own recipient, no Bcc header and no open recipients
            // (QMF derives the envelope from these headers). MEASURED: the
            // placeholder "To: undisclosed-recipients:;" got such a copy refused
            // with 554 5.7.1 Spam message rejected — see GpgEngine::sendPgpMime.
            Copy c; c.to = QStringList(addr);
            if (!envelopeFor(one, &c.body)) return;
            copies << c;
        }
        if (copies.isEmpty()) {
            emit sendFinished(false, QStringLiteral("No recipient — nothing to send."));
            return;
        }
    }

    qWarning() << "[smime] send: built" << copies.size() << "CMS message(s), deferring QMF";
    const bool hasAtt = !attachments.isEmpty();
    QString dom = fromAddr.section('@', 1).trimmed(); if (dom.isEmpty()) dom = QStringLiteral("localhost");
    QList<QByteArray> messages;
    for (int ci = 0; ci < copies.size(); ++ci) {
        const Copy &c = copies.at(ci);
        QByteArray rfc;
        rfc += "From: " + account.fromAddress().toString().toUtf8() + "\r\n";
        // A blind copy carries no To/Cc: QMF builds the SMTP envelope FROM these
        // headers, so naming the open recipients would deliver this copy to them
        // twice. The group placeholder is not an e-mail address, so QMF's
        // isEmailAddress() filter keeps it out of the envelope.
        if (c.to.isEmpty() && c.cc.isEmpty())
            rfc += "To: undisclosed-recipients:;\r\n";
        else
            rfc += "To: " + c.to.join(QStringLiteral(", ")).toUtf8() + "\r\n";
        if (!c.cc.isEmpty())  rfc += "Cc: " + c.cc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
        if (!c.bcc.isEmpty()) rfc += "Bcc: " + c.bcc.join(QStringLiteral(", ")).toUtf8() + "\r\n";
        rfc += "Subject: " + subject.toUtf8() + "\r\n";
        rfc += "Date: " + QMailTimeStamp::currentDateTime().toString().toUtf8() + "\r\n";
        // Copy index: the copies of one send are built in the same millisecond,
        // and duplicate Message-IDs invite servers to treat them as one mail.
        rfc += "Message-ID: <" + QByteArray::number(QDateTime::currentMSecsSinceEpoch())
             + "." + QByteArray::number(ci) + ".sm@" + dom.toUtf8() + ">\r\n";
        // No User-Agent — see the encrypted send path in GpgEngine.cpp.
        rfc += "MIME-Version: 1.0\r\n";
        rfc += c.body;
        messages << rfc;
    }

    QTimer::singleShot(0, this, [this, accId, messages, hasAtt]() {
        for (const QByteArray &rfc : messages)
            if (!smimeStoreInOutbox(accId, rfc, hasAtt)) {
                emit sendFinished(false, QStringLiteral("Could not store the message in the outbox."));
                return;
            }
        emit sendFinished(true, QString());
        smimeTransmit(accId);
    });
}

// Store one built message in the outbox. Split from the transmit half so a
// send with blind copies can queue several messages (one per audience) and
// then push them with a single transmit — QMF has no per-message send.
bool SmimeEngine::smimeStoreInOutbox(const QMailAccountId &accId, const QByteArray &rfc, bool hasAttachments)
{
    QMailAccount account(accId);
    // Heap-allocate and INTENTIONALLY never delete — same QMF ABI-shim destructor
    // UAF crash as the PGP send path (see GpgEngine::storeAndTransmit). Sends are
    // infrequent; leaking one small QMailMessage avoids invoking the crashing
    // destructor. C++17 guaranteed elision → no temporary is created/destroyed.
    QMailMessage *msg = new QMailMessage(QMailMessage::fromRfc2822(rfc));
    msg->setParentAccountId(accId);
    QMailFolderId outbox = account.standardFolder(QMailFolder::OutboxFolder);
    if (!outbox.isValid()) outbox = QMailFolderId(static_cast<quint64>(1));
    msg->setParentFolderId(outbox);
    msg->setStatus(QMailMessage::Outgoing, true);
    msg->setStatus(QMailMessage::ContentAvailable, true);
    msg->setStatus(QMailMessage::Read, true);
    msg->setStatus(QMailMessage::Outbox, true);
    msg->setStatus(QMailMessage::HasAttachments, hasAttachments);
    if (!QMailStore::instance()->addMessage(msg)) {
        qWarning() << "[smime] send: addMessage FAILED";
        return false;
    }
    qWarning() << "[smime] send: stored msg" << msg->id().toULongLong() << "in outbox — queued";
    return true;
}

// Push the account's whole outbox (messageserver does the actual SMTP).
void SmimeEngine::smimeTransmit(const QMailAccountId &accId)
{
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
    QFile::remove(m_home + QStringLiteral("/trustlist.txt"));
    cleanupTempFiles();
    invalidateCerts();
    log(QStringLiteral("store wiped"));
    emit certsChanged();
}

// ---------------------------------------------------------------------------
// Decrypt (Stufe 1, milestone 2) + round-trip self-test
// ---------------------------------------------------------------------------

void SmimeEngine::decryptFile(const QString &pathOrPkcs7, const QString &passphrase)
{
    const QVariantMap noSig;
    if (!m_available) { emit decryptFinished(false, QString(), QString(), QStringLiteral("gpgsm not available"), noSig, -1); return; }
    QByteArray data;
    QString p = pathOrPkcs7;
    if (p.startsWith(QStringLiteral("file://"))) p = p.mid(7);
    if (QFileInfo::exists(p)) { QFile f(p); if (f.open(QIODevice::ReadOnly)) { data = f.readAll(); f.close(); } }
    else data = pathOrPkcs7.toUtf8();
    if (data.isEmpty()) { emit decryptFinished(false, QString(), QString(), QStringLiteral("empty input"), noSig, -1); return; }

    QByteArray out, err;
    QStringList a;
    a << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
      << QStringLiteral("--passphrase-fd") << QStringLiteral("0")
      << QStringLiteral("--decrypt");
    // gpgsm reads the passphrase from fd 0 first; feed passphrase then the CMS.
    QByteArray pass = passphrase.toUtf8() + "\n";
    bool ok = runGpgsm(a, pass + data, &out, &err, 90000);
    pass.fill(0);
    if (ok && !out.isEmpty())
        emit decryptFinished(true, QString::fromUtf8(out), QString(), QString(), noSig, -1);
    else
        emit decryptFinished(false, QString(), QString(), smimeHumanErr(err), noSig, -1);
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
