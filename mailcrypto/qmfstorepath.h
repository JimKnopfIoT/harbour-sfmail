#ifndef QMFSTOREPATH_H
#define QMFSTOREPATH_H

#include <QDir>
#include <QFileInfo>
#include <QString>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QVariant>
#include <qmailnamespace.h>

// The file a stored message lives in, for both engines — one rule, so the two
// cannot drift apart again (they did: one resolved relative entries, the other
// read the store writable).
//
// Asked from the store database, read-only, without building a QMailMessage
// (that can freeze the app, and crashes it where the framework on the device
// is newer than the one we built against). QMF knows where its store lives —
// legacy ~/.qmf or the XDG data directory — so that is asked, never guessed.
// Entries are "qmfstoragemanager:<path>"; old installations still carry paths
// relative to the store's mail directory, which QMF resolves the same way.
static inline QString qmfMessageFile(int messageId)
{
    const QString base = QDir::cleanPath(QMail::dataPath());
    const QString dbPath = base + QStringLiteral("/database/qmailstore.db");
    if (!QFileInfo::exists(dbPath)) return QString();
    const QString conn = QStringLiteral("sfmail_mailfile_%1").arg(messageId);
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
                QString mf = q.value(0).toString();
                const int c = mf.indexOf(QLatin1Char(':'));
                if (c > 0 && mf.left(c).contains(QStringLiteral("storagemanager"), Qt::CaseInsensitive))
                    mf = mf.mid(c + 1);
                if (!mf.isEmpty())
                    path = mf.startsWith(QLatin1Char('/')) ? mf
                         : (base + QStringLiteral("/mail/") + mf);
            }
            db.close();
        }
    }
    QSqlDatabase::removeDatabase(conn);
    return path;
}

#endif
