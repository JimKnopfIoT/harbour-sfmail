#ifndef SMIMEENGINE_H
#define SMIMEENGINE_H

#include <QObject>
#include <QVariantList>
#include <QStringList>
#include <QByteArray>

class QNetworkAccessManager;
class QMailTransmitAction;
class QMailAccountId;

// S/MIME (PKI/MIME) backend: a thin QProcess wrapper around the modern bundled
// gpgsm (2.2.x) that harbour-sfmail already ships under
// /usr/share/harbour-sfmail/gpg/. We reuse that stack (this is an add-on; it does
// NOT bundle its own GnuPG). Operates on its OWN gpgsm home dir so the OpenPGP
// keyring of harbour-sfmail stays untouched. Passphrases via loopback.
//
// Stufe-0 (manually) proven: import a Volksverschlüsselung .p12 (3 key pairs) +
// chain, encrypt to the keyEncipherment cert, decrypt back to plaintext. This
// class turns that proof into code (see SmimeEngine.cpp for the gotchas).
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
    // Import an S/MIME .p12/.pfx (with private key[s]) plus its CA chain. gpgsm
    // cannot parse a Windows/Volksverschlüsselung .p12 directly, so we repack it
    // with OpenSSL: dump everything, split the (up to 3) key pairs, build one
    // clean p12 per key, import each via gpgsm, import the chain, and trust the
    // root CA via trustlist.txt. Result via importFinished().
    Q_INVOKABLE void importP12(const QString &p12Path, const QString &passphrase,
                               const QString &chainPemPath = QString());

    // Generate a brand-new SELF-SIGNED S/MIME certificate (RSA-4096) for this
    // identity and import it — for users without an external CA (e.g. now that
    // Volksverschlüsselung is gone). The cert carries the MANDATORY e-mail
    // attributes so Outlook/Thunderbird accept it for signing AND encryption:
    // extendedKeyUsage=emailProtection [[smime-signer-emailprotection-eku]] and
    // keyUsage=digitalSignature,keyEncipherment, with the address in
    // subjectAltName. Protected by the given passphrase (mandatory; UI enforces
    // strength). Being self-signed it is its own root → trusted via trustlist (the
    // far side must still trust it once, like a first PGP-key exchange). Reuses the
    // proven importP12() path. Result via importFinished() + certsChanged().
    Q_INVOKABLE void generateCert(const QString &name, const QString &email,
                                  const QString &passphrase, int days = 730);

    // Import X.509 certificate(s) WITHOUT a private key: a PEM/DER cert, a PKCS#7
    // bundle (.p7b/.p7c), or a signed S/MIME message — the signer's certificate
    // (and chain) travel inside it. This is the "import sender's key" use case:
    // learn a correspondent's cert from their signed mail so you can later encrypt
    // to them. Result via importFinished().
    Q_INVOKABLE void importCertFromFile(const QString &pathOrData);

    // --- working directly on a received QMF message (by id) ----------------
    // What kind of S/MIME a stored message is: "encrypted" (pkcs7-mime enveloped),
    // "signed" (multipart/signed pkcs7-signature) or "" (not S/MIME). Read from the
    // message's Content-Type without constructing a QMailMessage.
    Q_INVOKABLE QString messageKind(int messageId);
    // Import the sender's certificate(s) carried inside a (signed) message. Result
    // via importFinished(); roots auto-fetched via AIA like every import.
    Q_INVOKABLE void importCertFromMessage(int messageId);
    // Is the sender's certificate of a SIGNED message NOT yet in the store? (Used to
    // show the import button only when needed.) Encrypted/none → false.
    Q_INVOKABLE bool senderCertMissing(int messageId);
    // Decrypt an encrypted (pkcs7-mime) message. Handles a nested opaque signed-data
    // layer (unwraps it to the real text) and stashes the sender's cert for an
    // explicit import. Result via decryptFinished() (signer == "cert-available" when
    // a sender certificate was found).
    Q_INVOKABLE void decryptMessage(int messageId, const QString &passphrase);
    // Import the sender certificate(s) stashed by the last decryptMessage(). Result
    // via importFinished(); roots auto-fetched via AIA.
    Q_INVOKABLE void importPendingSenderCert();

    // All certificates currently in the gpgsm store (secret ones flagged).
    Q_INVOKABLE QVariantList listCerts();
    // The PEM (armored X.509) of one stored certificate — for "show / export".
    Q_INVOKABLE QString exportCert(const QString &fingerprint);
    // Export a stored certificate INCLUDING its private key as a PKCS#12 (.p12) and
    // save it to the user's Documents folder as sfmail-smime-<short>.p12 — a portable
    // backup importable into Outlook/Thunderbird/another device. Needs the key's
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
    void certsChanged();
    void importFinished(bool ok, int imported, const QString &error);
    void decryptFinished(bool ok, const QString &text, const QString &signer, const QString &error);
    void roundTripFinished(bool ok, const QString &text, const QString &error);
    void sendFinished(bool ok, const QString &error);
    // Verbose progress line for the test UI / debug.log.
    void logLine(const QString &line);

private:
    // Run the bundled gpgsm with our common args (homedir, agent/dirmngr program,
    // disable-crl-checks, batch). Returns true on exit 0; out/err filled.
    bool runGpgsm(const QStringList &args, const QByteArray &stdinData,
                  QByteArray *out, QByteArray *err, int timeoutMs = 60000);
    // Run the system openssl. ok = exit 0.
    bool runOpenssl(const QStringList &args, const QByteArray &stdinData,
                    QByteArray *out, QByteArray *err, int timeoutMs = 60000);
    // Does this openssl understand the -legacy flag (OpenSSL 3.x)?
    bool opensslHasLegacy();

    // Auto-complete the trust chain. For every stored cert whose issuer is NOT yet
    // present, read the issuer-cert location from the cert's OWN data (the X.509
    // Authority Information Access "CA Issuers" URL) and download + import it, up to
    // the self-signed root. NOTHING about the source is hard-coded — the URL always
    // comes out of the certificate itself. Called after each import.
    void completeChainViaAia();
    // The AIA "CA Issuers" URL carried inside the cert with this fingerprint (""
    // if the cert has no such pointer).
    QString aiaCaIssuers(const QString &fingerprint);
    // Blocking HTTP GET (Qt network, works inside the sandbox with the Internet
    // permission). Empty on error/timeout.
    QByteArray httpGet(const QString &url, int timeoutMs);
    // (Re)write trustlist.txt with the self-signed ROOT certs currently in the store.
    void updateTrustlist();
    // True if EVERY certificate in `pem` is already present in the store (by SHA-1
    // fingerprint). Used to hide "import" once nothing new is left to import.
    bool certsAllInStore(const QByteArray &pem);
    // Extract the signer cert(s) PEM from a (signed) message; empty if none.
    QByteArray senderCertPemOf(int messageId);
    // The account's own signing/encryption cert fingerprint for an address ("" if
    // none). usage 's' = signing cert, 'e' = encryption cert.
    QString ownCertFpr(const QString &email, char usage);
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
    // ALSO embeds the sender's encryption certificate + CA chain — so the recipient
    // (Outlook/Thunderbird) can harvest the encryption cert and reply encrypted, the
    // way other clients do. gpgsm --sign embeds only the signer cert, so we export
    // the signing key from gpgsm and re-sign with openssl's -certfile. Returns empty
    // on failure (caller falls back to a plain gpgsm sign). errOut gets the reason.
    QByteArray signWithChain(const QByteArray &inner, const QString &signFpr,
                             const QString &fromAddr, const QString &passphrase,
                             QByteArray *errOut);
    // Shared QMF tail: parse RFC2822 → outbox → transmit (S/MIME copy of GpgEngine).
    void smimeStoreAndTransmit(const QMailAccountId &accId, const QByteArray &rfc, bool hasAttachments);

    void log(const QString &s);

    QString m_stack;     // /usr/share/harbour-sfmail/gpg
    QString m_gpgsm;     // m_stack/bin/gpgsm
    QString m_openssl;   // /usr/bin/openssl
    QString m_lib;       // m_stack/lib  (LD_LIBRARY_PATH)
    QString m_agent;     // m_stack/bin/gpg-agent
    QString m_dirmngr;   // m_stack/bin/dirmngr
    QString m_home;      // our private gpgsm home
    bool m_available = false;
    int m_legacy = -1;   // -1 unknown, 0 no, 1 yes
    QNetworkAccessManager *m_nam = nullptr;
    QMailTransmitAction *m_tx = nullptr;
    QByteArray m_pendingSenderCertPem;   // sender certs from the last decrypt
    QVariantList m_lastDecAttachments;   // attachments from the last decryptMessage()
    // Cache the embedded signer certs of the most recently decrypted message, so
    // "Encryption info" can list the signature certs WITHOUT asking the passphrase
    // again (the user already decrypted the mail).
    int m_lastDecMsgId = -1;
    QByteArray m_lastDecSignerPem;
};

#endif // SMIMEENGINE_H
