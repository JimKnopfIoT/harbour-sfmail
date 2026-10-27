#include "MailSearchModel.h"

#include <QDebug>
#include <algorithm>

#include <qmailaccount.h>
#include <qmailaccountconfiguration.h>
#include <qmailaccountkey.h>
#include <qmailaddress.h>
#include <qmailmessage.h>
#include <qmailmessagesortkey.h>
#include <qmailstore.h>
#include <qmailtimestamp.h>

// The result list stops here; the page says so when it does.
static const uint kLocalLimit = 500;
// Per account and question; the server reports how many it held back.
static const uint kRemoteLimit = 100;

MailSearchModel::MailSearchModel(QObject *parent)
    : QAbstractListModel(parent)
{
    if (QMailStore *st = QMailStore::instance()) {
        connect(st, &QMailStore::messagesRemoved, this, &MailSearchModel::onMessagesRemoved);
        connect(st, &QMailStore::messagesUpdated, this, &MailSearchModel::onMessagesUpdated);
    }
}

MailSearchModel::~MailSearchModel()
{
    cancel();
}

int MailSearchModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_rows.size();
}

QVariant MailSearchModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_rows.size())
        return QVariant();
    const Row &r = m_rows.at(index.row());
    switch (role) {
    case MessageIdRole:     return static_cast<int>(r.id);
    case AccountIdRole:     return static_cast<int>(r.account);
    case FolderIdRole:      return static_cast<int>(r.folder);
    case SubjectRole:       return r.subject;
    case SenderNameRole:    return r.senderName;
    case SenderAddressRole: return r.senderAddress;
    case DateRole:          return r.date;
    case PreviewRole:       return r.preview;
    case ReadRole:          return bool(r.status & QMailMessage::Read);
    case EncryptedRole:     return bool(r.status & QMailMessage::HasEncryption);
    case AttachmentsRole:   return bool(r.status & QMailMessage::HasAttachments);
    }
    return QVariant();
}

QHash<int, QByteArray> MailSearchModel::roleNames() const
{
    return {
        { MessageIdRole,     "messageId" },
        { AccountIdRole,     "accountId" },
        { FolderIdRole,      "folderId" },
        { SubjectRole,       "subject" },
        { SenderNameRole,    "senderName" },
        { SenderAddressRole, "senderAddress" },
        { DateRole,          "date" },
        { PreviewRole,       "preview" },
        { ReadRole,          "read" },
        { EncryptedRole,     "encrypted" },
        { AttachmentsRole,   "hasAttachments" },
    };
}

void MailSearchModel::setAccountIds(const QVariantList &v)
{ if (v != m_accountIds) { m_accountIds = v; emit filterChanged(); } }
void MailSearchModel::setConditions(const QVariantList &v)
{ if (v != m_conditions) { m_conditions = v; emit filterChanged(); } }
void MailSearchModel::setMatchAll(bool v)
{ if (v != m_matchAll) { m_matchAll = v; emit filterChanged(); } }
// A JavaScript Date arrives as a local QDateTime; null and invalid dates clear.
static QDate toDay(const QVariant &v)
{
    if (!v.isValid() || v.isNull()) return QDate();
    return v.toDate();
}
void MailSearchModel::setDateFrom(const QVariant &v)
{ const QDate d = toDay(v); if (d != m_dateFrom) { m_dateFrom = d; emit filterChanged(); } }
void MailSearchModel::setDateTo(const QVariant &v)
{ const QDate d = toDay(v); if (d != m_dateTo) { m_dateTo = d; emit filterChanged(); } }
void MailSearchModel::setAttachments(int v)
{ if (v != m_attachments) { m_attachments = v; emit filterChanged(); } }

// --- building the question ---------------------------------------------------

// The conditions as the framework can take them. Sender, recipients and
// subject become keys; NOT is the Excludes comparator, which the IMAP side
// turns into "NOT (...)". The message text cannot be a key — a search action
// carries exactly one text, matched as "contains". With OR it therefore
// becomes a question of its own, and the answers are joined.
QList<MailSearchModel::Branch> MailSearchModel::branches() const
{
    QList<QMailMessageKey> keys;
    QString text;
    for (const QVariant &c : m_conditions) {
        const QVariantMap m = c.toMap();
        const QString field = m.value(QStringLiteral("field")).toString();
        const QString value = m.value(QStringLiteral("value")).toString().trimmed();
        const bool negate = m.value(QStringLiteral("negate")).toBool();
        if (value.isEmpty()) continue;
        const QMailDataComparator::InclusionComparator cmp =
            negate ? QMailDataComparator::Excludes : QMailDataComparator::Includes;
        if (field == QLatin1String("from"))
            keys << QMailMessageKey::sender(value, cmp);
        else if (field == QLatin1String("to"))
            keys << QMailMessageKey::recipients(value, cmp);
        else if (field == QLatin1String("subject"))
            keys << QMailMessageKey::subject(value, cmp);
        else if (field == QLatin1String("text") && !negate && text.isEmpty())
            text = value;
    }

    QList<Branch> out;
    if (m_matchAll) {
        Branch b;
        for (const QMailMessageKey &k : keys) b.key &= k;
        b.body = text;
        if (!b.key.isEmpty() || !b.body.isEmpty()) out << b;
    } else {
        if (!keys.isEmpty()) {
            Branch b;
            for (const QMailMessageKey &k : keys) b.key |= k;
            out << b;
        }
        if (!text.isEmpty()) {
            Branch b;
            b.body = text;
            out << b;
        }
    }
    return out;
}

QList<quint64> MailSearchModel::wantedAccounts() const
{
    QList<quint64> out;
    for (const QVariant &v : m_accountIds) {
        const quint64 id = v.toULongLong();
        if (id > 0 && !out.contains(id)) out << id;
    }
    if (out.isEmpty()) {
        const QMailAccountKey key =
            // The int overload: the enum one changed its signature between
            // framework versions and is missing on newer devices.
            QMailAccountKey::messageType(int(QMailMessage::Email), QMailDataComparator::Includes)
            & QMailAccountKey::status(QMailAccount::Enabled, QMailDataComparator::Includes);
        for (const QMailAccountId &id : QMailStore::instance()->queryAccounts(key))
            out << id.toULongLong();
    }
    return out;
}

bool MailSearchModel::hasImap(quint64 account)
{
    const QMailAccountConfiguration cfg{QMailAccountId(account)};
    return cfg.services().contains(QStringLiteral("imap4"));
}

// Everything that narrows without being something the server understands.
QMailMessageKey MailSearchModel::narrowing() const
{
    QMailMessageKey k = QMailMessageKey::status(QMailMessage::Removed, QMailDataComparator::Excludes);

    QMailAccountIdList accounts;
    for (quint64 id : wantedAccounts()) accounts << QMailAccountId(id);
    k &= QMailMessageKey::parentAccountId(accounts);

    // Day boundaries in local time; the store compares in UTC.
    if (m_dateFrom.isValid())
        k &= QMailMessageKey::timeStamp(QDateTime(m_dateFrom, QTime(0, 0)).toUTC(),
                                        QMailDataComparator::GreaterThanEqual);
    if (m_dateTo.isValid())
        k &= QMailMessageKey::timeStamp(QDateTime(m_dateTo.addDays(1), QTime(0, 0)).toUTC(),
                                        QMailDataComparator::LessThan);
    if (m_attachments == 1)
        k &= QMailMessageKey::status(QMailMessage::HasAttachments, QMailDataComparator::Includes);
    else if (m_attachments == 2)
        k &= QMailMessageKey::status(QMailMessage::HasAttachments, QMailDataComparator::Excludes);
    return k;
}

QString MailSearchModel::problem(bool remote) const
{
    int texts = 0;
    bool any = false;
    for (const QVariant &c : m_conditions) {
        const QVariantMap m = c.toMap();
        if (m.value(QStringLiteral("value")).toString().trimmed().isEmpty()) continue;
        any = true;
        if (m.value(QStringLiteral("field")).toString() == QLatin1String("text")) {
            if (m.value(QStringLiteral("negate")).toBool()) return QStringLiteral("text-negated");
            if (++texts > 1) return QStringLiteral("text-twice");
        }
    }
    // Without a condition the server would be asked for every message there
    // is, and would hand over the headers of all of them.
    if (remote && !any) return QStringLiteral("server-needs-condition");
    if (!any && !m_dateFrom.isValid() && !m_dateTo.isValid() && m_attachments == 0)
        return QStringLiteral("nothing");
    return QString();
}

// --- running it --------------------------------------------------------------

bool MailSearchModel::searchLocal()
{
    if (!problem(false).isEmpty()) return false;
    cancel();
    beginResetModel();
    m_rows.clear();
    endResetModel();
    emit countChanged();
    m_skipped = m_failed = m_remaining = 0;
    m_truncated = false;

    const QMailMessageKey base = narrowing();
    QList<Job> jobs;
    const QList<Branch> bs = branches();
    if (bs.isEmpty()) {
        Job j;
        j.filter = base;
        jobs << j;
    }
    for (const Branch &b : bs) {
        Job j;
        j.filter = base & b.key;
        j.body = b.body;
        jobs << j;
    }
    qWarning() << "[xsearch] local:" << jobs.size() << "question(s)";
    start(jobs, QStringLiteral("local"));
    return true;
}

bool MailSearchModel::searchRemote()
{
    if (!problem(true).isEmpty()) return false;
    cancel();
    m_skipped = m_failed = m_remaining = 0;

    const QMailMessageKey base = narrowing();
    const QList<Branch> bs = branches();
    QList<Job> jobs;
    for (quint64 acc : wantedAccounts()) {
        if (!hasImap(acc)) { ++m_skipped; continue; }
        for (const Branch &b : bs) {
            Job j;
            j.remote = true;
            j.account = acc;
            // Only what the server understands; the account routes the
            // question and is not sent.
            j.filter = QMailMessageKey::parentAccountId(QMailAccountId(acc)) & b.key;
            j.body = b.body;
            j.check = base & b.key;
            jobs << j;
        }
    }
    qWarning() << "[xsearch] remote:" << jobs.size() << "question(s),"
               << m_skipped << "account(s) without server search";
    if (jobs.isEmpty()) {
        setState(QStringLiteral("failed"));
        return false;
    }
    start(jobs, QStringLiteral("remote"));
    return true;
}

void MailSearchModel::start(const QList<Job> &jobs, const QString &state)
{
    m_jobs = jobs;
    setState(state);
    runNext();
}

void MailSearchModel::runNext()
{
    while (!m_jobs.isEmpty()) {
        m_current = m_jobs.takeFirst();
        m_found.clear();

        // A local question without text is a plain store query; nothing to wait for.
        if (!m_current.remote && m_current.body.isEmpty()) {
            const QMailMessageIdList ids = QMailStore::instance()->queryMessages(
                m_current.filter, QMailMessageSortKey::timeStamp(Qt::DescendingOrder), kLocalLimit);
            if (ids.size() >= int(kLocalLimit)) m_truncated = true;
            addMatches(ids, QMailMessageKey());
            continue;
        }

        QMailSearchAction *a = new QMailSearchAction(this);
        m_action = a;
        connect(a, &QMailSearchAction::messageIdsMatched, this,
                [this, a](const QMailMessageIdList &ids) {
                    if (a == m_action) m_found += ids;
                });
        // Older frameworks emit remainingMessagesCount(uint), newer ones
        // remainingMessagesCountChanged(uint) and keep the old name for a
        // getter. Connected by name at run time, so the plugin links against
        // neither and loads on both.
        const QMetaObject *mo = a->metaObject();
        const char *sig = mo->indexOfSignal("remainingMessagesCountChanged(uint)") >= 0
                ? SIGNAL(remainingMessagesCountChanged(uint))
                : mo->indexOfSignal("remainingMessagesCount(uint)") >= 0
                  ? SIGNAL(remainingMessagesCount(uint)) : nullptr;
        if (sig) connect(a, sig, this, SLOT(onRemainingCount(uint)));
        connect(a, &QMailServiceAction::activityChanged, this,
                [this, a](QMailServiceAction::Activity act) {
                    if (a != m_action) return;
                    if (act == QMailServiceAction::Successful) finishJob(true);
                    else if (act == QMailServiceAction::Failed) finishJob(false);
                });
        if (m_current.remote)
            a->searchMessages(m_current.filter, m_current.body, QMailSearchAction::Remote,
                              kRemoteLimit, QMailMessageSortKey::timeStamp(Qt::DescendingOrder));
        else
            a->searchMessages(m_current.filter, m_current.body, QMailSearchAction::Local,
                              kLocalLimit, QMailMessageSortKey::timeStamp(Qt::DescendingOrder));
        return;
    }
    setState(QStringLiteral("done"));
}

void MailSearchModel::finishJob(bool ok)
{
    QMailSearchAction *a = m_action;
    m_action.clear();
    if (a) a->deleteLater();

    if (!ok) {
        ++m_failed;
        qWarning() << "[xsearch]" << (m_current.remote ? "remote" : "local")
                   << "question failed, account" << m_current.account;
    } else {
        if (!m_current.remote && m_found.size() >= int(kLocalLimit)) m_truncated = true;
        addMatches(m_found, m_current.check);
    }
    m_found.clear();
    runNext();
}

// Checks what came back against the full filter (for the server: the date,
// the attachment state and the accounts it never saw) and adds the new ones.
void MailSearchModel::addMatches(const QMailMessageIdList &ids, const QMailMessageKey &check)
{
    if (ids.isEmpty()) return;
    QMailMessageIdList keep = ids;
    if (!check.isEmpty())
        keep = QMailStore::instance()->queryMessages(QMailMessageKey::id(ids) & check);

    QList<Row> fresh;
    for (const QMailMessageId &id : keep) {
        const quint64 v = id.toULongLong();
        bool known = false;
        for (const Row &r : m_rows) if (r.id == v) { known = true; break; }
        for (const Row &r : fresh) if (r.id == v) { known = true; break; }
        if (!known) fresh << loadRow(v);
    }
    if (fresh.isEmpty()) return;

    beginResetModel();
    m_rows += fresh;
    std::stable_sort(m_rows.begin(), m_rows.end(),
                     [](const Row &a, const Row &b) { return a.date > b.date; });
    if (m_rows.size() > int(kLocalLimit)) {
        m_rows.erase(m_rows.begin() + kLocalLimit, m_rows.end());
        m_truncated = true;
    }
    endResetModel();
    emit countChanged();
}

// Metadata only — a full message loaded here can crash where the device's mail
// framework is newer than the one this was built against.
MailSearchModel::Row MailSearchModel::loadRow(quint64 id)
{
    Row r;
    const QMailMessageMetaData meta{QMailMessageId(id)};
    r.id = id;
    r.account = meta.parentAccountId().toULongLong();
    r.folder = meta.parentFolderId().toULongLong();
    r.subject = meta.subject();
    const QMailAddress from = meta.from();
    r.senderName = from.name();
    r.senderAddress = from.address();
    r.date = meta.date().toLocalTime();
    r.preview = meta.preview();
    r.status = meta.status();
    return r;
}

void MailSearchModel::onRemainingCount(uint n)
{
    if (sender() && sender() == m_action.data()) m_remaining += int(n);
}

void MailSearchModel::cancel()
{
    m_jobs.clear();
    if (QMailSearchAction *a = m_action) {
        m_action.clear();
        a->cancelOperation();
        a->deleteLater();
    }
    if (m_state == QLatin1String("local") || m_state == QLatin1String("remote"))
        setState(QStringLiteral("done"));
}

void MailSearchModel::clear()
{
    cancel();
    beginResetModel();
    m_rows.clear();
    endResetModel();
    emit countChanged();
    m_skipped = m_failed = m_remaining = 0;
    m_truncated = false;
    setState(QString());
}

void MailSearchModel::setState(const QString &s)
{
    if (s == QLatin1String("done") && m_failed > 0 && m_rows.isEmpty())
        m_state = QStringLiteral("failed");
    else
        m_state = s;
    emit stateChanged();
}

void MailSearchModel::onMessagesRemoved(const QMailMessageIdList &ids)
{
    for (const QMailMessageId &id : ids) {
        const quint64 v = id.toULongLong();
        for (int i = 0; i < m_rows.size(); ++i) {
            if (m_rows.at(i).id != v) continue;
            beginRemoveRows(QModelIndex(), i, i);
            m_rows.removeAt(i);
            endRemoveRows();
            emit countChanged();
            break;
        }
    }
}

void MailSearchModel::onMessagesUpdated(const QMailMessageIdList &ids)
{
    for (const QMailMessageId &id : ids) {
        const quint64 v = id.toULongLong();
        for (int i = 0; i < m_rows.size(); ++i) {
            if (m_rows.at(i).id != v) continue;
            m_rows[i] = loadRow(v);
            emit dataChanged(index(i), index(i));
            break;
        }
    }
}
