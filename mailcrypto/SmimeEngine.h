#ifndef SMIMEENGINE_H
#define SMIMEENGINE_H

#include <QObject>
#include <QVariantList>
#include <QStringList>
#include <QByteArray>
#include <QHash>
#include <QVariantMap>

class QNetworkAccessManager;
class QMailTransmitAction;
class QMailAccountId;

// S/MIME (PKI/MIME) backend: a QProcess wrapper around the gpgsm of the bundled
// GnuPG stack under /usr/share/harbour-sfmail/gpg/, plus the bundled openssl for
// the PKCS#12 plumbing gpgsm cannot do itself. Operates on its OWN gpgsm home
// dir so the OpenPGP keyring stays untouched. Passphrases via loopback / fd,
// never on a command line.
//
// Trust model (deliberate, see trustRoot()): the local store is the anchor.
// Certificates are shown to the user and imported on their say-so; a root
// becomes an anchor only when the user confirms it. Signatures are verified
// with gpgsm against that store — a message is called "signed" only after
// GOODSIG, never because of its Content-Type.
class SmimeEngine : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool available READ available CONSTANT)
    Q_PROPERTY(QString gnupgHome READ gnupgHome CONSTANT)

public:
    explicit SmimeEngine(QObject *parent = nullptr);

    bool available() const { return m_available; }
    QString gnupgHome() const { return m_home; }

    // --- Stufe 1, milestone 1: certificate import -------------------------
    // Pin ONE certificate for an address, for when several can encrypt. Empty
    // fingerprint clears the choice and returns to the automatic rule.
    Q_INVOKABLE void setPreferredCert(const QString &email, const QString &fingerprint);
    Q_INVOKABLE QString preferredCert(const QString &email);

    // Import an S/MIME .p12/.pfx (with private key[s]) plus its CA chain. gpgsm
    // cannot parse many real-world .p12 files directly, so we repack them
    // with OpenSSL: dump everything, split the (up to 3) key pairs, build one
    // clean p12 per key, import each via gpgsm, import the chain, and trust the
    // root CA via trustlist.txt. Result via importFinished().
    Q_INVOKABLE void importP12(const QString &p12Path, const QString &passphrase,
                               const QString &chainPemPath = QString());

    // Generate a brand-new SELF-SIGNED S/MIME certificate (RSA-4096) for this
    // identity and import it — for users without access to an external CA. The
    // cert carries the MANDATORY e-mail
    // attributes so common desktop clients accept it for signing AND encryption:
    // extendedKeyUsage=emailProtection and
    // keyUsage=digitalSignature,keyEncipherment, with the address in
    // subjectAltName. Protected by the given passphrase (mandatory; UI enforces
    // strength). Being self-signed it is its own root → trusted via trustlist (the
    // far side must still trust it once, like a first PGP-key exchange). Reuses the
    // proven importP12() path. Result via importFinished() + certsChanged().
    Q_INVOKABLE void generateCert(const QString &name, const QString &email,
                                  const QString &passphrase, int days = 730);

    // --- importing OTHER people's certificates: inspect first, then confirm -----
    // Read the certificate(s) from a source WITHOUT importing anything:
    //   source "message" → the CMS of the signed message with id `arg`
    //   source "pending" → the sender certs stashed by the last decryptMessage()
    //   source "file"    → a PEM/DER cert, PKCS#7 bundle or signed .eml at path `arg`
    // Returns what the confirmation dialog shows: every certificate with subject,
    // e-mail addresses, issuer, SHA-1 fingerprint, validity, CA/self-signed flags,
    // whether it is already in the store, and conflicts (a DIFFERENT certificate
    // already stored for one of its addresses); plus whether any leaf certificate
    // carries senderEmail. The batch is stashed for importInspected().
    Q_INVOKABLE QVariantMap inspectCertImport(const QString &source, const QString &arg,
                                              const QString &senderEmail);
    // Import the batch stashed by inspectCertImport(). trustRoots: also make the
    // self-signed root(s) IN THE BATCH trust anchors (trustlist). fetchAia: after
    // the import, download missing issuer certificates from the URLs inside the
    // certificates (https only, size-capped) — those are stored but NOT trusted.
    // Result via importFinished() + certsChanged().
    Q_INVOKABLE void importInspected(bool trustRoots, bool fetchAia);

    // --- working directly on a received QMF message (by id) ----------------
    // What kind of S/MIME a stored message is: "encrypted" (pkcs7-mime enveloped),
    // "signed" (multipart/signed pkcs7-signature) or "" (not S/MIME). Read from the
    // message's Content-Type without constructing a QMailMessage.
    Q_INVOKABLE QString messageKind(int messageId);
    // Verify the signature of a SIGNED (not encrypted) stored message with gpgsm.
    // Returns {status, trust, fpr, subject, emails, certInStore, note, error}:
    //   status "good"           GOODSIG and the chain ends in a trusted root
    //          "good-untrusted" GOODSIG, but the chain is not anchored in the store
    //          "bad"            BADSIG — altered or forged
    //          "nocert"         no signer certificate available — cannot verify
    //          "error"          gpgsm failed (see error)
    //          "none"           not a signed message
    // Result is cached per message until the store changes.
    Q_INVOKABLE QVariantMap verifyMessage(int messageId);
    // Is the sender's certificate of a SIGNED message NOT yet in the store? (Used to
    // show the import button only when needed.) Encrypted/none → false.
    Q_INVOKABLE bool senderCertMissing(int messageId);
    // Decrypt an encrypted (pkcs7-mime) message. A nested signed layer (opaque or
    // multipart/signed) is verified with gpgsm and unwrapped to the real text; the
    // sender's cert is stashed for an explicit, confirmed import. Result via
    // decryptFinished(): signer = "cert-new" | "cert-present" | "", sig = the
    // verification map (see verifyMessage), messageId echoes the argument so a
    // page can ignore results that belong to another message.
    Q_INVOKABLE void decryptMessage(int messageId, const QString &passphrase);

    // All certificates currently in the gpgsm store (secret ones flagged).
    Q_INVOKABLE QVariantList listCerts();
    // The PEM (armored X.509) of one stored certificate — for "show / export".
    Q_INVOKABLE QString exportCert(const QString &fingerprint);
    // Export a stored certificate INCLUDING its private key as a PKCS#12 (.p12) and
    // save it to the user's Documents folder as sfmail-smime-<short>.p12 — a portable
    // backup importable into other clients or another device. Needs the key's
    // passphrase; the .p12 is protected with that same passphrase. Returns the saved
    // path ("" on failure). Only certs that have a private key can be exported.
    Q_INVOKABLE QString saveP12ToDocuments(const QString &fingerprint, const QString &passphrase);
    // Delete a single certificate (and its private key, if any) from the store.
    // Emits certsChanged() so the list refreshes. Returns true on success.
    Q_INVOKABLE bool deleteCert(const QString &fingerprint);
    // Full certificate info for a stored S/MIME message, for the "Encryption info"
    // view and for debugging: the recipient (encryption) certs the message is
    // encrypted to — yours AND the other party's — each with its issuer chain up to
    // the root CA, PLUS the signature certificates embedded in the message, PLUS a
    // raw debug dump. passphrase is optional: without it the recipient list + chains
    // still show; WITH it the encrypted body is opened so the embedded signature
    // certs can be listed too. Returns a QVariantMap consumed by SmimeInfoPage.
    Q_INVOKABLE QVariantMap messageCertInfo(int messageId, const QString &passphrase);

    // --- sending (CMS → pkcs7-mime, via QMF) -------------------------------
    // Do we hold a (usable) certificate to encrypt TO this e-mail address? Used by
    // the composer to offer S/MIME encryption only when it can actually work.
    Q_INVOKABLE bool hasCertFor(const QString &email);
    // Send an S/MIME message: encrypt the body+attachments to each recipient's
    // certificate (+ to self) and/or sign with the account's own key, wrap as
    // application/pkcs7-mime, store in the outbox and transmit. Result via
    // sendFinished(). passphrase is only needed when signing.
    Q_INVOKABLE void sendSmime(int accountId, const QString &subject,
                               const QStringList &to, const QStringList &cc,
                               const QStringList &bcc, const QString &body,
                               const QVariantList &attachments,
                               bool encrypt, bool sign, const QString &passphrase);

    // Attachments of a PLAIN (unencrypted) message, parsed straight from its raw
    // RFC822 file in QMF — works on BOTH SFOS 4.6 (no EmailMessage.attachmentModel)
    // and 5.x, so the UI can list/open/save them uniformly. Needs the full message
    // downloaded. Each entry: {name,mimeType,path,url,isImage,size}.
    Q_INVOKABLE QVariantList plainAttachments(int messageId);

    // Attachments recovered from the LAST decryptMessage() (S/MIME mails carry their
    // body + files inside the decrypted MIME, just like PGP/MIME). The UI reads this
    // right after decryptFinished() and renders them with the same open/save UI as
    // the PGP path. Returns + clears the list.
    Q_INVOKABLE QVariantList takeLastAttachments();

    // Forget everything (wipe our gpgsm home) — handy while iterating on import.
    Q_INVOKABLE void wipeStore();

    // --- Stufe 1, milestone 2: receive ------------------------------------
    // Decrypt an S/MIME message: pathOrPkcs7 is a path to a .p7m/.eml or the raw
    // application/pkcs7-mime body. Result via decryptFinished().
    Q_INVOKABLE void decryptFile(const QString &pathOrPkcs7, const QString &passphrase);

    // Round-trip self-test (Stufe-0 reproduction): encrypt a sample to our own
    // encryption cert, then decrypt it — proves the store is usable end-to-end.
    Q_INVOKABLE void roundTripTest(const QString &passphrase);

signals:
    void preferredCertChanged(const QString &email, const QString &fingerprint);
    void certsChanged();
    void importFinished(bool ok, int imported, const QString &error);
    void decryptFinished(bool ok, const QString &text, const QString &signer, const QString &error,
                         const QVariantMap &sig, int messageId);
    void roundTripFinished(bool ok, const QString &text, const QString &error);
    void sendFinished(bool ok, const QString &error);
    // Verbose progress line for the test UI / debug.log.
    void logLine(const QString &line);

private:
    // Run the bundled gpgsm with our common args (homedir, agent/dirmngr program,
    // disable-crl-checks, batch). Returns true on exit 0; out/err filled.
    bool runGpgsm(const QStringList &args, const QByteArray &stdinData,
                  QByteArray *out, QByteArray *err, int timeoutMs = 60000);
    // Run the system openssl. ok = exit 0. A non-empty passEnv is exported as
    // SFMAIL_PASS for -passin/-passout env:SFMAIL_PASS — NEVER pass a passphrase
    // as "pass:<x>" on the command line, /proc/<pid>/cmdline is world-readable.
    bool runOpenssl(const QStringList &args, const QByteArray &stdinData,
                    QByteArray *out, QByteArray *err, int timeoutMs = 60000,
                    const QString &passEnv = QString());
    // Does this openssl understand the -legacy flag (OpenSSL 3.x)?
    bool opensslHasLegacy();

    // Complete the issuer chain ON REQUEST: for every stored cert whose issuer is
    // not present, read the "CA Issuers" URL from the cert's own Authority
    // Information Access extension and download + import that issuer, up to the
    // self-signed root. https only, size-capped; nothing fetched is trusted.
    void completeChainViaAia();
    // The AIA "CA Issuers" URL carried inside the cert with this fingerprint (""
    // if the cert has no such pointer).
    QString aiaCaIssuers(const QString &fingerprint);
    // Blocking HTTPS GET, capped at maxBytes. Empty on error/timeout/oversize.
    QByteArray httpGet(const QString &url, int timeoutMs, int maxBytes);
    // Trust anchors (trustlist.txt): add / remove one root, list them.
    void trustRoot(const QString &fpr);
    void untrustRoot(const QString &fpr);
    QStringList trustedRoots() const;
    // gpgsm --verify on a raw signed message (opaque signed-data or
    // multipart/signed). contentOut receives the verified content (the opaque
    // payload, or the raw signed part). See verifyMessage() for the map.
    QVariantMap verifyRaw(const QByteArray &raw, QByteArray *contentOut);
    // Describe PEM certificate(s) for the import dialog (see inspectCertImport).
    QVariantMap describeCertsPem(const QByteArray &pem, const QString &senderEmail);
    // Forget cached listCerts()/verify results after the store changed.
    void invalidateCerts();
    // Remove leftovers of interrupted operations (temp dirs, scratch files).
    void cleanupTempFiles();
    // True if EVERY certificate in `pem` is already present in the store (by SHA-1
    // fingerprint). Used to hide "import" once nothing new is left to import.
    bool certsAllInStore(const QByteArray &pem);
    // Extract the signer cert(s) PEM from a (signed) message; empty if none.
    QByteArray senderCertPemOf(int messageId);
    // The account's own signing/encryption cert fingerprint for an address ("" if
    // none). usage 's' = signing cert, 'e' = encryption cert.
    QString ownCertFpr(const QString &email, char usage);
    // One certificate for an address, chosen by usage/validity/age — see the .cpp.
    QString pickCertFpr(const QString &email, char usage, bool needSecret);
    QString prefStorePath() const;
    // The decoded "ext key usage:" line of the cert with this fingerprint (e.g.
    // "emailProtection (suggested)" or "clientAuth"); empty if the cert carries no
    // extKeyUsage extension (= valid for any purpose). Used to reject the
    // authentication cert (clientAuth only) when selecting a signing cert.
    QString extKeyUsage(const QString &fingerprint);
    // Resolve a certificate fingerprint against the store into a display map
    // {fpr, inStore, subject, hasSecret, keyUsage, validity, chain:[{subject,fpr,role}]}.
    // `all` is the cached listCerts() result (avoids re-listing per cert).
    QVariantMap certEntry(const QString &fpr, const QVariantList &all);
    // Produce an opaque signed-data CMS (DER) of `inner`, signed with signFpr, that
    // ALSO embeds the sender's encryption certificate + CA chain — so the
    // recipient's client can harvest the encryption cert and reply encrypted, the
    // way desktop clients expect. gpgsm --sign embeds only the signer cert, so we export
    // the signing key from gpgsm and re-sign with openssl's -certfile. Returns empty
    // on failure (caller falls back to a plain gpgsm sign). errOut gets the reason.
    QByteArray signWithChain(const QByteArray &inner, const QString &signFpr,
                             const QString &fromAddr, const QString &passphrase,
                             QByteArray *errOut);
    // Shared QMF tail: parse RFC2822 → outbox → transmit (S/MIME copy of GpgEngine).
    bool smimeStoreInOutbox(const QMailAccountId &accId, const QByteArray &rfc, bool hasAttachments);
    void smimeTransmit(const QMailAccountId &accId);

    void log(const QString &s);

    QString m_stack;     // /usr/share/harbour-sfmail/gpg
    QString m_gpgsm;     // m_stack/bin/gpgsm
    QString m_openssl;   // /usr/bin/openssl
    QString m_lib;       // m_stack/lib  (LD_LIBRARY_PATH)
    QString m_agent;     // m_stack/bin/gpg-agent
    QString m_home;      // our private gpgsm home
    bool m_available = false;
    int m_legacy = -1;   // -1 unknown, 0 no, 1 yes
    QNetworkAccessManager *m_nam = nullptr;
    QMailTransmitAction *m_tx = nullptr;
    bool m_aiaRunning = false;           // re-entrancy guard (httpGet spins an event loop)
    QVariantList m_certCache;            // listCerts() result until the store changes
    bool m_certCacheValid = false;
    QHash<int, QVariantMap> m_verifyCache;   // verifyMessage() per message id
    QByteArray m_inspectPem;             // batch stashed by inspectCertImport()
    QVariantMap m_inspectInfo;
    QByteArray m_pendingSenderCertPem;   // sender certs from the last decrypt
    QVariantList m_lastDecAttachments;   // attachments from the last decryptMessage()
    // Cache the embedded signer certs of the most recently decrypted message, so
    // "Encryption info" can list the signature certs WITHOUT asking the passphrase
    // again (the user already decrypted the mail).
    int m_lastDecMsgId = -1;
    QByteArray m_lastDecSignerPem;
};

#endif // SMIMEENGINE_H
