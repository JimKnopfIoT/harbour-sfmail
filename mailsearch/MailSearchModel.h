#ifndef MAILSEARCHMODEL_H
#define MAILSEARCHMODEL_H

#include <QAbstractListModel>
#include <QDate>
#include <QDateTime>
#include <QList>
#include <QPointer>
#include <QVariantList>

#include <qmailmessagekey.h>
#include <qmailserviceaction.h>

// Combinable search over the mail store, and over IMAP servers on request.
//
// Conditions are {field, value, negate}: field is "from", "to", "subject" or
// "text" (the message text). They are joined with AND (matchAll) or OR, and
// narrowed by accounts, a date range and attachments. Only metadata is
// filtered here: the text of a message is searched by the mail framework,
// which sees the ciphertext of encrypted messages — they are found by sender
// and subject only. Nothing is decrypted and nothing is written.
//
// The server is only asked when searchRemote() is called. The framework turns
// sender, recipients and subject (with NOT) and the text into IMAP SEARCH, but
// silently DROPS the date and every status flag — a dropped condition makes
// the server's answer wider, never narrower. So the server is asked only what
// it understands, and every hit is checked against the full filter in the
// store before it is shown. Negated keys (~key) are not used at all: the
// framework would send them without the NOT.
class MailSearchModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(QVariantList accountIds READ accountIds WRITE setAccountIds NOTIFY filterChanged)
    Q_PROPERTY(QVariantList conditions READ conditions WRITE setConditions NOTIFY filterChanged)
    Q_PROPERTY(bool matchAll READ matchAll WRITE setMatchAll NOTIFY filterChanged)
    // A date (day, local time) or null for an open end.
    Q_PROPERTY(QVariant dateFrom READ dateFrom WRITE setDateFrom NOTIFY filterChanged)
    Q_PROPERTY(QVariant dateTo READ dateTo WRITE setDateTo NOTIFY filterChanged)
    // 0 = either, 1 = with attachments, 2 = without
    Q_PROPERTY(int attachments READ attachments WRITE setAttachments NOTIFY filterChanged)
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)
    // "" (nothing run), "local", "remote" (running), "done", "failed"
    Q_PROPERTY(QString state READ state NOTIFY stateChanged)
    // Accounts the last server search skipped (no IMAP) or that failed.
    Q_PROPERTY(int skippedAccounts READ skippedAccounts NOTIFY stateChanged)
    Q_PROPERTY(int failedAccounts READ failedAccounts NOTIFY stateChanged)
    // Matches the servers reported but did not hand over (search limit).
    Q_PROPERTY(int remainingOnServer READ remainingOnServer NOTIFY stateChanged)
    // The result list hit its cap; there may be more.
    Q_PROPERTY(bool truncated READ truncated NOTIFY stateChanged)

public:
    enum Roles {
        MessageIdRole = Qt::UserRole + 1,
        AccountIdRole,
        FolderIdRole,
        SubjectRole,
        SenderNameRole,
        SenderAddressRole,
        DateRole,
        PreviewRole,
        ReadRole,
        EncryptedRole,
        AttachmentsRole
    };

    explicit MailSearchModel(QObject *parent = nullptr);
    ~MailSearchModel() override;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    QVariantList accountIds() const { return m_accountIds; }
    void setAccountIds(const QVariantList &v);
    QVariantList conditions() const { return m_conditions; }
    void setConditions(const QVariantList &v);
    bool matchAll() const { return m_matchAll; }
    void setMatchAll(bool v);
    QVariant dateFrom() const { return m_dateFrom.isValid() ? QVariant(m_dateFrom) : QVariant(); }
    void setDateFrom(const QVariant &v);
    QVariant dateTo() const { return m_dateTo.isValid() ? QVariant(m_dateTo) : QVariant(); }
    void setDateTo(const QVariant &v);
    int attachments() const { return m_attachments; }
    void setAttachments(int v);

    QString state() const { return m_state; }
    int skippedAccounts() const { return m_skipped; }
    int failedAccounts() const { return m_failed; }
    int remainingOnServer() const { return m_remaining; }
    bool truncated() const { return m_truncated; }

    // Why the current filter cannot be run, as a code the page translates:
    // "" (fine), "text-negated", "text-twice", "nothing" (no condition and no
    // narrowing filter), "server-needs-condition" (only for remote).
    Q_INVOKABLE QString problem(bool remote) const;
    // Replaces the results with what the store holds.
    Q_INVOKABLE bool searchLocal();
    // Asks the IMAP servers and adds what they find to the current results.
    Q_INVOKABLE bool searchRemote();
    Q_INVOKABLE void cancel();
    Q_INVOKABLE void clear();

signals:
    void filterChanged();
    void countChanged();
    void stateChanged();

private slots:
    void onRemainingCount(uint n);

private:
    struct Row {
        quint64 id = 0;
        quint64 account = 0;
        quint64 folder = 0;
        QString subject;
        QString senderName;
        QString senderAddress;
        QDateTime date;
        QString preview;
        quint64 status = 0;
    };
    struct Branch {
        QMailMessageKey key;   // sender / recipients / subject only
        QString body;          // the message text, or empty
    };
    struct Job {
        bool remote = false;
        quint64 account = 0;   // remote only
        QMailMessageKey filter;
        QString body;
        QMailMessageKey check; // applied in the store to what a job returns
    };

    QList<Branch> branches() const;
    QMailMessageKey narrowing() const;   // accounts, dates, attachments, not removed
    QList<quint64> wantedAccounts() const;
    static bool hasImap(quint64 account);

    void start(const QList<Job> &jobs, const QString &state);
    void runNext();
    void finishJob(bool ok);
    void addMatches(const QMailMessageIdList &ids, const QMailMessageKey &check);
    static Row loadRow(quint64 id);
    void setState(const QString &s);
    void onMessagesRemoved(const QMailMessageIdList &ids);
    void onMessagesUpdated(const QMailMessageIdList &ids);

    QVariantList m_accountIds;
    QVariantList m_conditions;
    bool m_matchAll = true;
    QDate m_dateFrom;
    QDate m_dateTo;
    int m_attachments = 0;

    QList<Row> m_rows;
    QString m_state;
    int m_skipped = 0;
    int m_failed = 0;
    int m_remaining = 0;
    bool m_truncated = false;

    QList<Job> m_jobs;
    Job m_current;
    QMailMessageIdList m_found;
    QPointer<QMailSearchAction> m_action;
};

#endif // MAILSEARCHMODEL_H
