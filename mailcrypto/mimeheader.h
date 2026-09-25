#ifndef MIMEHEADER_H
#define MIMEHEADER_H

#include <QByteArray>
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

#endif
