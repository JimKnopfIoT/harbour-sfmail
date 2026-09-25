#ifndef BACKUPFILE_H
#define BACKUPFILE_H

#include <QByteArray>
#include <QFileDevice>
#include <QSaveFile>
#include <QString>

// Write a backup (a secret key, a .p12, a revocation certificate) so that it
// is either complete or not there at all: the bytes go into a temporary file
// that replaces the target only once everything reached the disk. Writing in
// place destroyed the previous backup of the same name whenever the new
// attempt failed half-way (a full disk). Readable by the owner only.
static inline bool writeBackupFile(const QString &path, const QByteArray &data)
{
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    if (f.write(data) != data.size()) {
        f.cancelWriting();
        return false;
    }
    return f.commit();
}

#endif
