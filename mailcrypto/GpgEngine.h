#ifndef GPGENGINE_H
#define GPGENGINE_H

#include <QObject>
#include <QTimer>
#include <QVariantList>
#include <QSet>
#include <QVariantMap>
#include <QStringList>
#include <QByteArray>
#include <QDateTime>
#include <functional>

class QMailTransmitAction;
class QMailAccountId;
class QNetworkAccessManager;

// OpenPGP engine on top of the GPGME library, driving the modern bundled
// GnuPG 2.2 stack (under /usr/share/harbour-sfmail/gpg) against the app's own
// keyring. The system gpg (2.0.4) is far too old to read modern keyrings, so
// we deliberately do NOT use the native path. Passphrases for sign/decrypt are
// handed to GPGME via the loopback callback (no pinentry needed).
class GpgEngine : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool available READ available CONSTANT)
    Q_PROPERTY(QString gnupgHome READ gnupgHome CONSTANT)
    Q_PROPERTY(QString appVersion READ appVersion CONSTANT)
    // PGP is always on (the app's core). S/MIME (PKI) is opt-in — when off, all
    // S/MIME menus/UI stay hidden so the app is slim for PGP-only users. Persisted.
    Q_PROPERTY(bool smimeEnabled READ smimeEnabled WRITE setSmimeEnabled NOTIFY smimeEnabledChanged)

public:
    explicit GpgEngine(QObject *parent = nullptr);
    QString appVersion() const;

    bool available() const { return m_available; }
    QString gnupgHome() const;

    // --- key listing / management (synchronous; these are fast) ------------
    Q_INVOKABLE QVariantList publicKeys(const QString &pattern = QString());
    Q_INVOKABLE QVariantList secretKeys(const QString &pattern = QString());
    Q_INVOKABLE QString exportPublicKey(const QString &fingerprint);
    // Armored export of the SECRET key, for backup. Needs the passphrase (loopback);
    // the exported block stays protected by that same passphrase. Empty on failure.
    Q_INVOKABLE QString exportSecretKey(const QString &fingerprint, const QString &passphrase);
    // Export the public (secret=false) or secret (secret=true) key and SAVE it into
    // the user's Documents folder as sfmail-<keyId>[-secret].asc. Returns the saved
    // path ("" on failure). The secret backup requires the passphrase. (Documents is
    // the one user dir reliably reachable in the sandbox on both devices.)
    Q_INVOKABLE QString saveKeyToDocuments(const QString &fingerprint, bool secret,
                                           const QString &passphrase = QString());
    // Everything we can show about one key: keyId, fingerprint, created, expires,
    // algo, bits, status, revoked/expired, hasSecret, all UIDs, all subkeys (each
    // with id/created/expires/algo/bits/caps), and the armored block ("armored").
    Q_INVOKABLE QVariantMap keyDetails(const QString &fingerprint);

    Q_INVOKABLE void importKeyFile(const QString &path);
    Q_INVOKABLE void importKeyText(const QString &armored);
    Q_INVOKABLE void deleteKey(const QString &fingerprint, bool deleteSecret);

    // Best-effort secure delete of a file at its REAL path (wherever the user picked
    // it: Downloads, Documents, /sdcard, …). Used to remove an import source file the
    // user no longer needs on the device. Overwrites then unlinks. Returns true if
    // the file was removed.
    // Re-send whatever is stuck in an account's outbox. QMF transmits the WHOLE
    // outbox of the account, there is no per-message send. Returns false when the
    // account id is not usable.
    Q_INVOKABLE bool retryOutbox(int accountId);
    // How many messages currently sit in that account's outbox (0 = nothing stuck).
    Q_INVOKABLE int outboxCount(int accountId);
    // Messages waiting in ANY account's outbox, and which accounts they belong
    // to ([{accountId, name}]). The reader shows this so mail that could not go
    // out is visible without opening the outbox folder of the right account.
    Q_INVOKABLE int outboxTotal();
    Q_INVOKABLE QVariantList outboxAccounts();
    // Try every account that still has something waiting.
    Q_INVOKABLE void retryAllOutboxes();
    // Cancel a running automatic retry schedule.
    Q_INVOKABLE void cancelRetries();
    // Minutes until the next automatic attempt, -1 when nothing is scheduled.
    Q_INVOKABLE int minutesToNextRetry();

    Q_INVOKABLE bool shredFile(const QString &path);

    // Copy a decrypted attachment out of the private cache into the user's Documents
    // folder (like the stock client's "save"), de-duplicating the name. Returns the
    // saved path ("" on failure).
    Q_INVOKABLE QString saveAttachmentToDocuments(const QString &cachePathOrUrl,
                                                  const QString &suggestedName);
    // Same, but into a destination folder the user chose ("Save as…" via the Sailfish
    // folder picker). Empty destFolder falls back to Documents. De-duplicates the name.
    Q_INVOKABLE QString saveAttachmentTo(const QString &cachePathOrUrl,
                                         const QString &suggestedName,
                                         const QString &destFolder);

    // Stage an attachment for "Open with…": copy it into ~/Downloads/sfmail/ (a
    // location other apps may read) and make it world-readable, then return the
    // path. Needed because decrypted attachments live in the app's private data
    // dir (~/.local/share/sfmail/…), which Sailjail hides from the target app —
    // opening from there shows 0 bytes / "corrupt" (per a field report). Overwrites
    // an existing staged copy so repeated opens don't pile up duplicates.
    Q_INVOKABLE QString stageForOpen(const QString &cachePathOrUrl,
                                     const QString &suggestedName);

    // True when the message's FULL content (body + all parts) is already on the
    // device. Lets the UI skip a needless downloadMessage() on open — which on a
    // POP3 account can otherwise trigger a server round-trip that drops the local
    // copy if the message was meanwhile deleted from the server (per a field report).
    // Reads metadata only (QMailMessageMetaData), never the full QMailMessage, so
    // it does NOT freeze the GUI thread.
    Q_INVOKABLE bool contentAvailable(int messageId);

    // Header fields the sender put INSIDE the encrypted part of the message that
    // was decrypted last (draft-autocrypt-lamps-protected-headers): from/to/cc/
    // subject/date, empty when the message carries none. For a blind copy this is
    // the only place the other recipients appear — the outer headers cannot name
    // them without delivering the copy to them.
    Q_INVOKABLE QVariantMap protectedHeaders() const { return m_lastProtectedHeaders; }

    // MIME size-limit override: when a decrypt hits the anti-DoS size cap, the UI can
    // offer "load this once without limit". liftSizeLimit() ignores the caps for the
    // next 15 minutes (auto-resets); sizeLimitLifted() reports the current state.
    Q_INVOKABLE void liftSizeLimit();
    Q_INVOKABLE bool sizeLimitLifted();

    // Generate a brand-new OpenPGP key pair IN the app keyring: an RSA-4096
    // primary (cert,sign) plus an RSA-4096 encryption subkey, protected by the
    // given passphrase (mandatory; the UI enforces strength). Highest sensible
    // security. Runs ASYNCHRONOUSLY — key-gen can take a while, so it must never
    // block the GUI thread. Progress via keyGenStarted(); result via
    // keyGenFinished(ok, fingerprint, error). On success keysChanged() also fires.
    // expiry is a gpg expire spec ("2y", "0" = never, "2027-12-31", …).
    Q_INVOKABLE void generateKey(const QString &name, const QString &email,
                                 const QString &passphrase,
                                 const QString &expiry = QStringLiteral("2y"));

    // --- key lifecycle: extend / revoke / publish --------------------------
    // Extend the primary key AND its subkeys to a new expiry (gpg expire-spec,
    // e.g. "2y"). Needs the passphrase (loopback). Result via keyOpFinished().
    Q_INVOKABLE void extendKey(const QString &fingerprint, const QString &expiry,
                               const QString &passphrase);
    // Whether a revocation certificate is on file for this key (gpg auto-creates one
    // in openpgp-revocs.d/ at generation; imported keys may not have one). Gates the
    // safe two-stage revoke in the UI.
    Q_INVOKABLE bool hasRevocationCert(const QString &fingerprint);
    // SAFE step 1: copy the key's revocation certificate (WITH gpg's protective
    // leading colon, so it can't be applied by accident) into Documents as
    // sfmail-<keyId>-revocation.asc. Does NOT revoke anything. Returns the path ("").
    Q_INVOKABLE QString saveRevocationCert(const QString &fingerprint);
    // DESTRUCTIVE step 2 (irreversible): apply the revocation certificate — strip the
    // protective colon and import it — so the key is marked revoked locally. The UI
    // MUST confirm first. Afterwards publish the key so others learn. keyOpFinished().
    Q_INVOKABLE void revokeKey(const QString &fingerprint);
    // Publish the PUBLIC key to keys.openpgp.org (the one verified keyserver). Async
    // HTTPS upload (VKS API). Result via keyOpFinished(). To make the e-mail itself
    // searchable the user must complete the verification mail keys.openpgp.org sends.
    Q_INVOKABLE void publishKey(const QString &fingerprint);

    // CLEAN 1-click import (mirrors the S/MIME sender-cert flow): inspect a public
    // key WITHOUT importing, stash it, and report it via keyImportCandidate() so the
    // UI can warn about revoked/expired keys or a conflicting key already stored for
    // the same address. The user then confirms with importPendingKey(). Never
    // auto-imports. inspectKeyForImport takes armored text; the *File variant reads
    // a key file (armored or binary).
    Q_INVOKABLE void inspectKeyForImport(const QString &armored, const QString &senderEmail = QString());
    Q_INVOKABLE void inspectKeyFileForImport(const QString &path, const QString &senderEmail = QString());

    // Resolve a MISSING key: look up the exact wantedKeyId on keys.openpgp.org,
    // falling back to the sender's email. NEVER imports on its own — whatever is
    // found is stashed and reported via keyCandidate() (key-id, UIDs, fingerprint,
    // match yes/no) so the user can verify and decide (importPendingKey()).
    // Result/no-result via keyFetchFinished(); progress via keyFetchStarted().
    Q_INVOKABLE void resolveMissingKey(const QString &wantedKeyId, const QString &email);
    // Import the key stashed by resolveMissingKey() after a keyMismatch().
    Q_INVOKABLE void importPendingKey();

    // --- crypto (may block briefly) ---------------------------------------
    // Inline-PGP encrypt (+ optional sign). passphrase is only needed when
    // signFingerprint is set. Result is an ASCII-armored block.
    Q_INVOKABLE void encrypt(const QStringList &recipientFingerprints,
                             const QString &plaintext, const QString &signFingerprint,
                             const QString &passphrase);
    // Inline clear-text signature (gpg --clearsign), NO encryption. The signed,
    // armored text comes back via encryptFinished() (same path as inline encrypt,
    // so the QML send flow is reused). Needs the passphrase + the signing key.
    Q_INVOKABLE void clearSign(const QString &text, const QString &signFingerprint,
                               const QString &passphrase);
    // Inline-PGP decrypt/verify of an armored block.
    Q_INVOKABLE void decryptText(const QString &armored, const QString &passphrase);
    // PGP/MIME: decrypt the encrypted part (a file containing an armored block,
    // e.g. the QMF message part "encrypted.asc"), then fully parse the inner
    // MIME: readable text PLUS every attachment/image (written to a private
    // cache so QML can open/show them). pathOrUrl may be a file:// URL or path.
    Q_INVOKABLE void decryptMimeFile(const QString &pathOrUrl, const QString &passphrase);

    // --- PGP/MIME sending (bypasses Nemo.Email, talks to QMF directly) -----
    // Build a real multipart/encrypted (RFC 3156) message: the body text and
    // every attachment are assembled into an inner MIME entity, encrypted (and
    // optionally signed) as a whole, wrapped as multipart/encrypted, stored in
    // the account's outbox and transmitted. attachments = list of maps with
    // keys name, path (or url), mimeType. Result via sendFinished().
    // blindCopies carries the blind recipients, each as a map {address, fprs}: one
    // SEPARATE message is built per entry, encrypted ONLY to that entry's keys, so
    // no recipient learns of any other. A single message encrypted to everyone
    // would name every recipient key in the clear (one PKESK packet each), which
    // is exactly what a blind copy must not do. The open recipients (To/Cc) get
    // their own message without any Bcc header at all.
    Q_INVOKABLE void sendPgpMime(int accountId, const QString &subject,
                                 const QStringList &to, const QStringList &cc,
                                 const QVariantList &blindCopies, const QString &bodyText,
                                 const QVariantList &attachments,
                                 const QStringList &recipientFingerprints,
                                 const QString &signFingerprint, const QString &passphrase);

    // Build a real multipart/signed (RFC 3156) message: the body + attachments are
    // assembled into an inner MIME entity, a DETACHED OpenPGP signature is computed
    // over its canonical CRLF bytes, and both are wrapped as multipart/signed,
    // stored in the outbox and transmitted. NO encryption — anyone can read it, but
    // the recipient can verify the sender holds the key. Result via sendFinished().
    Q_INVOKABLE void signPgpMime(int accountId, const QString &subject,
                                 const QStringList &to, const QStringList &cc,
                                 const QStringList &bcc, const QString &bodyText,
                                 const QVariantList &attachments,
                                 const QString &signFingerprint, const QString &passphrase);

    // --- diagnostics (synchronous, read-only) ------------------------------
    // Without decrypting, inspect an encrypted block: which recipient key IDs it
    // is addressed to, each resolved against the keyring with FULL detail (UIDs,
    // creation date, algo/length, fingerprint, revoked/expired status, whether
    // we hold the secret key) and whether the message is decryptable. src may be
    // the inline armored body, or a path/URL to the encrypted.asc part.
    // Returns a map: { format, found, canDecrypt, signedSeen, error,
    //                  recipients: [ { keyId, inKeyring, status, revoked,
    //                  expired, hasSecret, uids, created, algo, bits, fpr } ] }.
    Q_INVOKABLE QVariantMap encryptionInfo(const QString &src);

    // --- raw headers + sender reputation -----------------------------------
    // Full raw RFC822 header block read directly from the QMF content file (via
    // qmailstore.db id→mailfile). Does NOT construct a QMailMessage (that freezes
    // the app). Sanitised + hard-wrapped for safe rendering.
    Q_INVOKABLE QString rawHeaders(int messageId);
    // Parse sender signals from the raw headers: From/Return-Path domains (+
    // mismatch), SPF/DKIM/DMARC, originating IP/host. Map also carries "rawText".
    Q_INVOKABLE QVariantMap analyzeSender(int messageId);
    // Check ONLY the given sender IP and domain against DNS blacklists. Per-list
    // result via blacklistResult(); blacklistDone() at the end. Never sends the
    // user's own data.
    Q_INVOKABLE void checkBlacklists(const QString &ip, const QString &domain,
                                     const QStringList &linkDomains = QStringList());

    // Actively verify SPF (is originIp allowed to send for mailFromDomain?) and
    // DMARC (policy + alignment for fromDomain) ourselves via DNS — independent
    // of any Authentication-Results header. Results via spfResult()/dmarcResult().
    Q_INVOKABLE void checkAuth(const QString &fromDomain, const QString &mailFromDomain,
                               const QString &originIp, const QString &dkimDomain);

    // --- "verified signed" memory ------------------------------------------
    // A PGP signature inside an encrypted message is only known AFTER decrypt.
    // We persist which message ids verified as signed, so the list can badge
    // them afterwards (QMF's own hasSignature never sees PGP-in-ciphertext).
    Q_INVOKABLE void rememberSigned(int messageId, const QString &signer);
    Q_INVOKABLE bool isSigned(int messageId);
    Q_INVOKABLE QString signerOf(int messageId);

    // User's preferred default sending account (persisted). 0 = none chosen.
    Q_INVOKABLE int defaultAccountId();
    Q_INVOKABLE void setDefaultAccountId(int accountId);

    // --- Templates -----------------------------------------------------------
    // A persistent, LOCAL "Templates" folder per account (created on first save;
    // not server-synchronized, so an IMAP folder-list sync won't delete it). A
    // template is an ordinary message kept in that folder — reused for composing
    // without being consumed, and only removed when the user deletes it.
    Q_INVOKABLE int templatesFolderId(int accountId, bool create);
    Q_INVOKABLE int saveTemplate(int accountId, const QString &subject,
                                 const QStringList &to, const QStringList &cc,
                                 const QStringList &bcc, const QString &body,
                                 const QString &cryptoKind, bool encrypt, bool sign);
    Q_INVOKABLE QVariantMap templateInfo(int messageId);
    // List the account's templates directly from the store (id + subject + crypto
    // choice), independent of the folder-list UI. The FolderListModel does not
    // reliably surface a local custom folder on every account type (POP3), so the
    // Templates view queries the folder's messages itself instead of relying on it.
    Q_INVOKABLE QVariantList listTemplates(int accountId);
    // Remove a single template (local only — never a server removal record).
    Q_INVOKABLE bool deleteTemplate(int messageId);

    // --- Drafts --------------------------------------------------------------
    // Save the current message as a draft in the account's Drafts folder, using
    // the SAME proven path as send/templates (self-built RFC2822 + fromRfc2822 +
    // heap-leak). The native EmailMessage.saveDraft() uses incremental QMF setters
    // that intermittently crash on POP3 (first save) — the class the send path
    // already avoids. Reuse templateInfo(id) to read a draft back for editing.
    Q_INVOKABLE int saveDraft(int accountId, const QString &subject,
                              const QStringList &to, const QStringList &cc,
                              const QStringList &bcc, const QString &body,
                              const QString &cryptoKind, bool encrypt, bool sign);
    // Remove a draft after it was sent or replaced (local only).
    Q_INVOKABLE bool deleteDraft(int messageId);

    bool smimeEnabled();
    void setSmimeEnabled(bool on);

signals:
    // Progress of the automatic retry schedule, for the UI: attempt number (1-based),
    // total attempts, minutes until the next one (-1 = no further attempt).
    // Something entered or left an outbox — the banner re-reads outboxTotal().
    void outboxChanged();
    void retryScheduled(int attempt, int total, int minutes);
    void retryStopped(const QString &reason);

    void keysChanged();
    void importFinished(bool ok, int imported, const QString &error);
    void keyDeleted(bool ok, const QString &error);
    void keyGenStarted();
    void keyGenFinished(bool ok, const QString &fingerprint, const QString &error);
    // Generic result for extend / revoke / publish (message is user-facing).
    void keyOpFinished(bool ok, const QString &message);
    void sizeLimitChanged();
    // A decrypt hit the MIME size cap and it was NOT lifted — the UI can offer to
    // reload this message once without the limit.
    void oversizedContent();
    void encryptFinished(bool ok, const QString &armored, const QString &error);
    // sig = the typed verification result (see signatureInfo in the .cpp):
    // status "" | good | bad | nokey | revoked | key-expired | sig-expired |
    // error, plus fpr, uid, emails and validity. signedBy stays as the one-line
    // rendering for the places that only display text.
    void decryptFinished(bool ok, const QString &text, const QString &signedBy, const QString &error,
                         const QVariantMap &sig);
    // Rich result for PGP/MIME: attachments is a list of maps with keys
    // name, mimeType, path, isImage.
    void decryptMimeFinished(bool ok, const QString &text, const QString &signedBy,
                             const QVariantList &attachments, const QVariantMap &sig,
                             const QString &error);
    void sendFinished(bool ok, const QString &error);
    void signedChanged();
    void defaultAccountChanged();
    void smimeEnabledChanged();
    void keyFetchStarted();
    void keyFetchFinished(bool ok, const QString &message);
    // A key was found on the keyserver. NEVER auto-imported — the UI shows it and
    // the user decides (importPendingKey()). matchesUsedKey == true means the key
    // this message used IS this key (its primary or an encryption subkey); false
    // means the address publishes a DIFFERENT key than the message used.
    void keyCandidate(const QString &foundKeyId, const QString &foundUids,
                      bool matchesUsedKey, const QString &foundFpr);
    // A public key from a message awaits the user's import decision. info carries:
    // keyId, fpr, uids, emails, created, expires, algo, bits, revoked, expired,
    // valid, inKeyring (exact key already present), conflicts (a list of maps
    // {fpr,keyId,uid,email,revoked,expired} for DIFFERENT keys already stored for
    // the same address), and — when a sender address was given —
    // senderEmail/senderKnown/senderMatches (does a UID address equal the mail's
    // From). Confirm with importPendingKey().
    void keyImportCandidate(const QVariantMap &info);
    void blacklistResult(const QString &name, const QString &status, const QString &detail);
    void blacklistDone();
    void spfResult(const QString &result, const QString &info);
    void dmarcResult(const QString &policy, const QString &verdict, const QString &info);

private:
    // Delete every file in the plaintext caches (decrypted attachments, the
    // copies staged under Downloads for "open with"). Run at startup and on
    // quit — decrypted mail must not outlive the session that opened it.
    void purgePlaintextCaches();
    QMailTransmitAction *transmitAction();
    void rememberOutboxAccount(quint64 acc);
    // Socket paths of the GnuPG agents (OpenPGP home, S/MIME home).
    QStringList m_agentSockets;
    QStringList m_agentHomes;             // same order, for readable log lines

    QVariantList listKeys(bool secret, const QString &pattern);
    // Fetch the first URL that returns a public-key block; cb gets the armored
    // bytes (empty if none of the URLs yielded a key).
    void httpGetFirst(const QStringList &urls, int idx, std::function<void(QByteArray)> cb);
    // Synchronous encrypt (+ optional sign) of raw bytes; armored result in out,
    // human-readable error in errMsg.
    bool encryptRaw(const QStringList &recipientFingerprints, const QByteArray &plaintext,
                    const QString &signFingerprint, const QString &passphrase,
                    QByteArray *out, QString *errMsg);
    // Synchronous DETACHED armored signature over raw bytes (sig in out).
    // micalgOut receives the RFC 3156 micalg ("pgp-sha256"-style) matching the
    // hash the engine actually used.
    bool signRaw(const QByteArray &data, const QString &signFingerprint,
                 const QString &passphrase, QByteArray *out,
                 QString *micalgOut, QString *errMsg);
    // Deferred QMF build+store+transmit, posted from sendPgpMime via a 0-timer so
    // it never runs inline during a QML page transition (render-freeze otherwise).
    // `copies` = one entry per message to send, each a map with the keys
    // to/cc/bcc (QStringList) and cipher (QByteArray). Several entries only occur
    // when the message has blind copies; they are stored one after another and
    // transmitted together (QMF sends the whole outbox in one go anyway).
    void finishPgpMimeSend(int accountId, const QString &subject,
                           const QVariantList &copies, bool hasAttachments);
    void finishSignedMimeSend(int accountId, const QString &subject,
                              const QStringList &to, const QStringList &cc,
                              const QStringList &bcc, const QByteArray &signedInner,
                              const QByteArray &signature, const QString &micalg,
                              bool hasAttachments);
    // Shared tail for both PGP/MIME paths: parse the fully-built RFC2822 bytes,
    // store in the account's outbox (with local-folder fallback) and transmit.
    void storeAndTransmit(const QMailAccountId &accId, const QByteArray &rfc,
                          bool hasAttachments);
    // The two halves of storeAndTransmit, so several messages can be queued and
    // then sent with ONE transmit (blind copies).
    bool storeInOutbox(const QMailAccountId &accId, const QByteArray &rfc,
                       bool hasAttachments);
    void transmitOutbox(const QMailAccountId &accId);
    bool m_available;
    QMailTransmitAction *m_tx = nullptr;

    // Automatic re-send for a stuck outbox. The steps are minutes; the schedule
    // stops after the last one so a permanently refused message is not delivered
    // over and over — repeated attempts at a mail the server rejects for good only
    // harm the sender's reputation.
    QTimer m_retryTimer;
    int m_retryStep = -1;                 // index into kRetryMinutes, -1 = idle
    QSet<quint64> m_retryAccounts;        // accounts whose outbox we keep trying
    void scheduleRetry(const QMailAccountId &accId);
    void onTransmitFailed(const QString &error, int code);

    QNetworkAccessManager *m_nam = nullptr;
    int m_blPending = 0;
    QByteArray m_pendingKeyArmored;   // a "different" key awaiting user import
    QString m_pendingKeyId;
    QDateTime m_sizeLimitUntil;       // MIME size caps ignored until this time
    QVariantMap m_lastProtectedHeaders;   // protected headers of the last decrypt

    // SPF evaluator state (one check in flight at a time).
    void spfFetchRecord(const QString &domain, bool topLevel);
    void spfEval(const QString &record, bool topLevel);
    void spfDone();
    QString m_spfIp;
    QString m_spfTopQualifier;   // qualifier of the top-level "all"
    bool m_spfMatched = false;
    bool m_spfFinalized = false;
    int m_spfPending = 0;
    int m_spfBudget = 0;         // remaining DNS lookups (loop guard)
    // carried from checkAuth() into the DMARC step (run after SPF finishes)
    QString m_authFrom, m_authMailFrom, m_authDkim, m_authSpfResult;
    void finalizeSpf();
    void checkDmarc();
};

#endif // GPGENGINE_H
