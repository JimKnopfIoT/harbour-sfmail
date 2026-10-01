#ifndef MIMEHEADER_H
#define MIMEHEADER_H

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QString>

// Attachment names and media types come from files and from other programs
// (a file name, the system's share sheet). Written into a MIME header, a CR or
// LF would start a header of someone else's choosing — inside a message the
// user then signs — and a quote would end the parameter early.
static inline QByteArray mimeSafeName(const QByteArray &in)
{
    QByteArray out;
    out.reserve(in.size());
    for (const char c : in) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f || c == '"' || c == '\\') continue;
        out += c;
    }
    out = out.trimmed();
    return out.isEmpty() ? QByteArray("attachment") : out;
}

static inline QByteArray mimeSafeType(const QByteArray &in)
{
    static const QRegularExpression re(
        QStringLiteral("^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$"));
    const QString t = QString::fromLatin1(in).trimmed();
    return re.match(t).hasMatch() ? t.toLatin1() : QByteArray("application/octet-stream");
}

// A forwarded message travels as a part of its own, exactly as it was: the
// file holds a complete MIME entity (its Content-* header fields and body),
// which goes into the multipart/mixed unchanged — only line ends are made CRLF,
// as on the wire anyway. Returns false when the file cannot be read.
static inline bool appendVerbatimEntity(QByteArray *m, const QByteArray &boundary, const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QByteArray e = f.readAll();
    f.close();
    if (e.isEmpty()) return false;
    e.replace("\r\n", "\n");
    e.replace('\n', "\r\n");
    *m += "--" + boundary + "\r\n";
    *m += e;
    if (!m->endsWith("\r\n")) *m += "\r\n";
    return true;
}

// Write a forwarded original into the plaintext cache (0600, emptied with the
// session like the decrypted attachments). Returns the path, "" on failure.
static inline QString writeForwardFile(const QString &dir, const QByteArray &entity)
{
    QDir().mkpath(dir);
    QString path;
    for (int n = 0; n < 1000; ++n) {
        path = dir + QStringLiteral("/forwarded-%1.eml").arg(n);
        if (!QFileInfo::exists(path)) break;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return QString();
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    const bool ok = (f.write(entity) == entity.size()) && f.flush();
    f.close();
    if (!ok) { QFile::remove(path); return QString(); }
    return path;
}

#endif
