import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import Nemo.Email 0.1
import SFMail.Gpg 1.0

// Einzelne Nachricht lesen. PGP/MIME wird vom nativen QMF-Krypto-Backend
// erkannt: Signaturstatus + Verschlüsselung werden angezeigt, mit Buttons zum
// Prüfen/Entschlüsseln. (Inline-PGP folgt in Phase C über unseren PgpEngine.)
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property int messageId: 0
    // Inline-PGP (nicht PGP/MIME) wird vom nativen Pfad nicht erkannt — wir
    // entschlüsseln/prüfen den Body dann selbst über das gpg2-Plugin.
    property string _inlinePlain: ""
    property string _inlineInfo: ""

    // S/MIME (PKI): "encrypted" | "signed" | "" (recomputed once the body is here).
    property string _smimeKind: ""
    property string _smimeInfo: ""
    property string _smimePlain: ""
    property bool _smimeImportNeeded: false   // sender cert found AND not yet in store
    function _refreshSmime() {
        if (!Gpg.smimeEnabled) { page._smimeKind = ""; page._smimeImportNeeded = false; return }
        page._smimeKind = Smime.messageKind(page.messageId)
        // For signed mails we can check the store right away; for encrypted ones the
        // cert is inside, so the check happens after Decrypt.
        page._smimeImportNeeded = (page._smimeKind === "signed") ? Smime.senderCertMissing(page.messageId)
                                                                 : false
    }
    // Attachments recovered from a decrypted PGP/MIME message (list of maps with
    // keys name, mimeType, path, url, isImage, size).
    property var _mimeAttachments: []
    // The encrypted PGP/MIME part may need downloading first; we then resume the
    // requested action. _pendingAction is "" | "decrypt" | "inspect".
    property string _pendingAction: ""
    property string _pendingPassphrase: ""
    property string _pendingEncLoc: ""   // SFOS 4.6: encrypted part location being fetched
    property bool _waitingForPart: false
    property int _pendingKeyIndex: -1   // attachment index to import once downloaded
    property string _topNotice: ""      // transient info line at the top
    property bool _oversized: false     // decrypt hit the size cap (offer lift)
    // Signature result from OUR decryption ("Good signature from…", "Signed, but…").
    property string _sigResult: ""
    readonly property bool _bodyHasPgp: message.body.indexOf("-----BEGIN PGP MESSAGE-----") >= 0
    readonly property bool _bodyHasSignedBlock: message.body.indexOf("-----BEGIN PGP SIGNED MESSAGE-----") >= 0
    // "encrypted in any way" = native PGP/MIME OR an inline ciphertext block.
    readonly property bool _isEncrypted: message.encryptionStatus === EmailMessage.Encrypted || _bodyHasPgp
    // We have decrypted content available.
    readonly property bool _isDecrypted: _inlinePlain !== ""
    // Does this message actually carry an importable PUBLIC key? Strict so the
    // "Import sender's key" entry only shows when a key is plausibly present: the
    // inline armor marker, or an attachment that is a key (NEVER the encrypted.asc
    // ciphertext). The plugin re-validates by really parsing it before any import.
    readonly property bool _hasImportableKey: {
        var KEYHDR = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        if (page._inlinePlain && page._inlinePlain.indexOf(KEYHDR) >= 0) return true
        if (message.body && message.body.indexOf(KEYHDR) >= 0) return true
        for (var a = 0; a < page._mimeAttachments.length; ++a) {
            var nm = ("" + page._mimeAttachments[a].name).toLowerCase()
            var mt = ("" + page._mimeAttachments[a].mimeType).toLowerCase()
            if (nm.indexOf("encrypted.asc") >= 0) continue
            if (mt.indexOf("pgp-keys") >= 0 || nm.indexOf("pubkey") >= 0
                || nm.indexOf(".asc") >= 0 || nm.indexOf(".gpg") >= 0) return true
        }
        return _keyAttachmentIndex() >= 0
    }
    // A REAL native signature (ignore the bogus Failure/Unchecked states QMF
    // reports on plain unsigned mails).
    readonly property bool _hasNativeSig: message.signatureStatus === EmailMessage.SignedValid
                                          || message.signatureStatus === EmailMessage.SignedInvalid
                                          || message.signatureStatus === EmailMessage.SignedExpired
                                          || message.signatureStatus === EmailMessage.SignedMissing

    EmailAgent {
        id: emailAgent
        // SFOS 4.6 has no EmailMessage.attachmentModel — we download the encrypted
        // part via EmailAgent.downloadAttachment() and get its file path here.
        onAttachmentPathChanged: {
            if (page._pendingEncLoc !== "" && attachmentLocation === page._pendingEncLoc
                && ("" + filepath) !== "") {
                var a = page._pendingAction, pp = page._pendingPassphrase
                page._pendingEncLoc = ""; page._pendingAction = ""; page._pendingPassphrase = ""
                page._inlineInfo = ""
                page._runEncAction("" + filepath, a, pp)
            }
        }
    }

    Connections {
        target: Gpg
        // Inline-PGP (decryptText): plain body only.
        onDecryptFinished: {
            if (ok) {
                page._inlinePlain = text
                page._sigResult = signedBy
                page._inlineInfo = signedBy.length > 0 ? signedBy : qsTr("Decrypted")
                if (signedBy.length > 0) Gpg.rememberSigned(page.messageId, signedBy)
            } else {
                page._inlineInfo = error  // already human-friendly from the plugin
            }
        }
        // PGP/MIME (decryptMimeFile): body text + attachments/images.
        onDecryptMimeFinished: {
            if (ok) {
                page._inlinePlain = text !== "" ? text : qsTr("(no text — see attachments below)")
                page._mimeAttachments = attachments
                page._sigResult = signedBy
                page._inlineInfo = signedBy.length > 0 ? signedBy
                                   : (attachments.length > 0
                                      ? qsTr("Decrypted — %1 attachment(s)").arg(attachments.length)
                                      : qsTr("Decrypted"))
                if (signedBy.length > 0) Gpg.rememberSigned(page.messageId, signedBy)
            } else {
                page._inlineInfo = error
            }
        }
        onImportFinished: {
            page._topNotice = ok ? qsTr("Imported %1 key(s) into your keyring.").arg(imported)
                                 : qsTr("Key import failed: %1").arg(error)
        }
        // A key was found in the message → let the user confirm (with revoked/
        // expired/conflict warnings) before it actually lands in the keyring.
        onKeyImportCandidate: {
            pageStack.push(Qt.resolvedUrl("KeyImportDialog.qml"), { info: info })
        }
        // A decrypt hit the anti-DoS size cap → offer a one-time "load without limit".
        onOversizedContent: page._oversized = true
    }

    // "Save as…": let the user pick a destination folder, then copy the attachment.
    function _saveAs(src, name) {
        console.log("[diag] saveAs mid=" + page.messageId + " name=" + name + " src=" + src)
        pageStack.push(folderPickerComponent, { attSrc: src, attName: name })
    }
    Component {
        id: folderPickerComponent
        FolderPickerPage {
            property string attSrc: ""
            property string attName: ""
            allowedOrientations: defaultAllowedOrientations
            dialogTitle: qsTr("Save to folder")
            onSelectedPathChanged: {
                var p = Gpg.saveAttachmentTo(attSrc, attName, "" + selectedPath)
                console.log("[diag] saved mid=" + page.messageId + " -> " + p)
                page._topNotice = (p && p.length > 0)
                    ? qsTr("Saved to %1").arg(p) : qsTr("Could not save the attachment")
            }
        }
    }

    // Push the passphrase dialog and decrypt (shared by the Decrypt button and the
    // "load without limit" banner).
    function _decryptPrompt() {
        var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                 { info: qsTr("To decrypt this message") })
        dlg.accepted.connect(function() { page._ensureEncPart("decrypt", dlg.passphrase) })
    }

    EmailMessage {
        id: message
        messageId: page.messageId
        autoVerifySignature: true
        onMessageDownloaded: { message.read = true; page._noteLoaded(); page._prefetchEncPart(); page._retryPending(); page._retryPendingKey(); page._refreshSmime(); page._loadPlainAttachments() }
        onStoredMessageChanged: { page._noteLoaded(); page._prefetchEncPart(); page._retryPending(); page._retryPendingKey(); page._refreshSmime(); page._loadPlainAttachments() }
        onInlinePartsDownloaded: { page._noteLoaded(); page._retryPending(); page._retryPendingKey(); page._loadPlainAttachments() }
    }

    // Feedback for "Download full message": if the download actually produced new
    // content the notice flips to "downloaded"; if nothing arrives within a few
    // seconds the message was already complete (the call is a no-op then).
    Timer {
        id: dlNoticeTimer
        interval: 8000
        onTriggered: if (page._topNotice === qsTr("Downloading the full message…"))
                         page._topNotice = qsTr("The message is already fully downloaded.")
    }
    function _noteLoaded() {
        if (page._topNotice === qsTr("Downloading the full message…")) {
            dlNoticeTimer.stop()
            page._topNotice = qsTr("Message downloaded.")
        }
    }

    // Human-readable file size: < 1 MB in kB, ≥ 1 MB in MB.
    function _fmtSize(bytes) {
        var b = Number(bytes) || 0
        if (b >= 1048576) return (b / 1048576).toFixed(1) + " MB"
        return Math.max(1, Math.round(b / 1024)) + " kB"
    }

    // Plain (unencrypted) mails: list attachments straight from the raw MIME (works
    // on SFOS 4.6 too, which has no EmailMessage.attachmentModel). Encrypted/PGP/
    // S/MIME mails fill _mimeAttachments via their decrypt handlers instead.
    function _loadPlainAttachments() {
        // Only ENCRYPTED content goes through the decrypt path (which fills
        // _mimeAttachments). Plain AND signed-but-readable mails are parsed here.
        if (message.encryptionStatus === EmailMessage.Encrypted) return
        if (page._bodyHasPgp) return
        if (page._smimeKind === "encrypted") return
        if (message.numberOfAttachments <= 0) return
        // On SFOS 5.x the native attachmentModel works (and stores parts separately,
        // so the raw-MIME parse would find nothing) — use it there. Only on 4.6, which
        // has NO attachmentModel, do we parse attachments out of the raw message.
        if (message.attachmentModel) return
        var a = Smime.plainAttachments(page.messageId)
        if (a && a.length > 0) page._mimeAttachments = a
    }

    Component.onCompleted: {
        message.read = true
        // For PGP/MIME we need the encrypted.asc part on disk before we can
        // decrypt or inspect, so fetch the whole message eagerly.
        // Fetch the full message when needed: empty body, encrypted (need the
        // ciphertext part), OR it has attachments (we parse them from the raw MIME).
        // Only fetch from the server if the FULL content isn't already on the device.
        // Skipping the needless re-fetch on an already-complete message avoids a POP3
        // round-trip that can drop the local copy when the message was meanwhile
        // deleted from the server (a field data-loss report). contentAvailable() is a
        // metadata-only check → no GUI freeze. Safe for IMAP: a half-fetched message
        // (body but not attachments) is only PartialContentAvailable → still downloads.
        var _ready = Gpg.contentAvailable(page.messageId)
        var _needDl = !_ready && (message.body === "" || message.encryptionStatus === EmailMessage.Encrypted
                || message.numberOfAttachments > 0)
        console.log("[diag] open mid=" + page.messageId + " atts=" + message.numberOfAttachments
                + " bodyEmpty=" + (message.body === "") + " enc=" + message.encryptionStatus
                + " hasModel=" + (!!message.attachmentModel) + " contentAvail=" + _ready
                + " -> downloadMessage=" + _needDl)
        if (_needDl)
            message.downloadMessage()
        page._prefetchEncPart()
        page._refreshSmime()
        page._loadPlainAttachments()
    }

    // S/MIME results (the Smime singleton comes from SFMail.Gpg too).
    Connections {
        target: Smime
        onDecryptFinished: {
            if (ok) { page._smimePlain = text
                      page._mimeAttachments = Smime.takeLastAttachments()  // show/save like PGP
                      page._smimeImportNeeded = (signer === "cert-new")
                      page._smimeInfo = qsTr("Decrypted") }
            else {
                var e = ("" + error).toLowerCase()
                page._smimeInfo = (e.indexOf("not found") >= 0 || e.indexOf("certificate") >= 0)
                    ? qsTr("Your certificate isn't installed yet — open “S/MIME certificates” in the menu to import your .p12")
                    : qsTr("Decrypt failed: %1").arg(error)
            }
        }
        onImportFinished: {
            if (ok) page._smimeImportNeeded = false   // now in the store → hide button
            page._smimeInfo = ok ? qsTr("Sender certificate imported")
                                 : qsTr("Import: %1").arg(error)
        }
    }

    // Download the encrypted PGP/MIME part ahead of time so the first Decrypt /
    // Encryption-info tap succeeds (the attachment url is empty until fetched).
    function _prefetchEncPart() {
        if (message.encryptionStatus !== EmailMessage.Encrypted) return
        var i = _encPartIndex()
        if (i < 0) return
        if (("" + message.attachmentModel.url(i)) === "")
            message.downloadAttachment(message.attachmentModel.location(i))
    }

    // Locate the encrypted PGP/MIME part (e.g. "encrypted.asc") among the
    // attachments and return its local file path/URL ("" if not found).
    // Index of the encrypted PGP/MIME part among the attachments, or -1.
    function _encPartIndex() {
        var am = message.attachmentModel
        if (!am) return -1
        for (var i = 0; i < am.count; ++i) {
            var name = ("" + am.displayName(i)).toLowerCase()
            var mime = ("" + am.mimeType(i)).toLowerCase()
            if (name.indexOf("encrypted.asc") >= 0 || mime.indexOf("pgp") >= 0
                || mime.indexOf("octet-stream") >= 0)
                return i
        }
        if (am.count === 1) return 0   // single-part PGP/MIME → the ciphertext
        return -1
    }

    // file:// URL of the encrypted part if already on disk, otherwise "".
    function _encPartUrl() {
        var i = _encPartIndex()
        if (i < 0) return ""
        return ("" + message.attachmentModel.url(i))
    }

    // Ensure the encrypted part is downloaded, THEN run action: "decrypt"/"inspect".
    // The QMF attachment url stays empty until the part is fetched, so a plain
    // location is not a usable file path — we must download first.
    function _ensureEncPart(action, passphrase) {
        var am = message.attachmentModel

        // --- SFOS 5.x path: EmailMessage.attachmentModel is available ---
        if (am) {
            var i = _encPartIndex()
            if (i < 0) { page._inlineInfo = qsTr("Encrypted part not found"); return }
            var url = ("" + am.url(i))
            if (url !== "") { page._runEncAction(url, action, passphrase); return }
            page._pendingAction = action; page._pendingPassphrase = passphrase; page._waitingForPart = true
            page._inlineInfo = qsTr("Downloading encrypted part…")
            message.downloadAttachment(am.location(i))
            return
        }

        // --- SFOS 4.6 path: no attachmentModel. Use the attachments location list
        //     + EmailAgent.downloadAttachment(); the file path arrives via the
        //     agent's attachmentPathChanged signal (see EmailAgent above). ---
        var atts = message.attachments
        if (!atts || atts.length === 0) { page._inlineInfo = qsTr("Encrypted part not found"); return }
        // NB: on 4.6 message.attachments holds the display NAMES ("encrypted.asc"),
        // NOT QMF locations. EmailAgent.downloadAttachment() needs a location
        // "<msgId>-<part>" — passing a name segfaults QMF. The encrypted.asc is the
        // data part (part 2) of the multipart/encrypted, so build the location.
        var raw = "" + atts[atts.length - 1]
        var loc = /^[0-9]+-[0-9]+$/.test(raw) ? raw : ("" + page.messageId + "-2")
        page._pendingAction = action; page._pendingPassphrase = passphrase; page._pendingEncLoc = loc
        page._inlineInfo = qsTr("Downloading encrypted part…")
        emailAgent.downloadAttachment(page.messageId, loc)
    }

    function _runEncAction(url, action, passphrase) {
        if (action === "decrypt") {
            page._oversized = false   // reset; re-set by onOversizedContent if it trips again
            Gpg.decryptMimeFile(url, passphrase)
        } else if (action === "inspect") {
            pageStack.push(Qt.resolvedUrl("CryptoInfoPage.qml"),
                           { info: Gpg.encryptionInfo(url),
                             senderEmail: ("" + message.fromAddress),
                             importKey: function() { return page._importKeyFromMessage() } })
        }
    }

    // Called when the message/attachment store updates — resume a pending action
    // once the encrypted part has finished downloading.
    function _retryPending() {
        if (!page._waitingForPart || page._pendingAction === "") return
        var url = _encPartUrl()
        if (url === "") return
        page._waitingForPart = false
        var a = page._pendingAction, pp = page._pendingPassphrase
        page._pendingAction = ""; page._pendingPassphrase = ""
        if (page._inlineInfo === qsTr("Downloading encrypted part…")) page._inlineInfo = ""
        page._runEncAction(url, a, pp)
    }

    // --- Import the sender's public key from this message -------------------
    function _keyAttachmentIndex() {
        var am = message.attachmentModel
        if (!am) return -1
        for (var i = 0; i < am.count; ++i) {
            var name = ("" + am.displayName(i)).toLowerCase()
            var mime = ("" + am.mimeType(i)).toLowerCase()
            if (name.indexOf("encrypted.asc") >= 0) continue   // that's the ciphertext
            if (mime.indexOf("pgp-keys") >= 0 || name.indexOf(".asc") >= 0
                || name.indexOf(".gpg") >= 0 || name.indexOf("pubkey") >= 0
                || name.indexOf("public") >= 0 || name.indexOf("0x") >= 0)
                return i
        }
        return -1
    }

    // Try to import the sender's public key from this message. For an ENCRYPTED
    // mail the key (if included) sits in the DECRYPTED content, not the outer
    // attachments, so we look there first. Returns a status string for the caller
    // to show; "" means an import was started (result comes via importFinished).
    function _importKeyFromMessage() {
        page._topNotice = ""
        var KEYHDR = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        // Found a key → INSPECT it first (revoked/expired/conflict checks); the
        // actual import happens only after the user confirms in KeyImportDialog.
        // 1) inline key block in the decrypted text or the outer body
        var fromAddr = "" + message.fromAddress
        var texts = [page._inlinePlain, message.body]
        for (var t = 0; t < texts.length; ++t) {
            if (texts[t] && texts[t].indexOf(KEYHDR) >= 0) {
                Gpg.inspectKeyForImport(texts[t], fromAddr); return ""
            }
        }
        // 2) a key file among the DECRYPTED attachments
        for (var a = 0; a < page._mimeAttachments.length; ++a) {
            var att = page._mimeAttachments[a]
            var nm = ("" + att.name).toLowerCase()
            var mt = ("" + att.mimeType).toLowerCase()
            if (mt.indexOf("pgp-keys") >= 0 || nm.indexOf(".asc") >= 0 || nm.indexOf(".gpg") >= 0
                || nm.indexOf("pubkey") >= 0 || nm.indexOf("public") >= 0 || nm.indexOf("0x") >= 0) {
                Gpg.inspectKeyFileForImport("" + att.path, fromAddr); return ""
            }
        }
        // 3) a key file among the OUTER attachments (rare for encrypted mail)
        var i = _keyAttachmentIndex()
        if (i >= 0) {
            var url = ("" + message.attachmentModel.url(i))
            if (url !== "") {
                Gpg.inspectKeyFileForImport(url.indexOf("file://") === 0 ? url.substring(7) : url, fromAddr); return ""
            }
            page._pendingKeyIndex = i
            message.downloadAttachment(message.attachmentModel.location(i))
            return qsTr("Downloading key…")
        }
        return qsTr("No PGP key found in this message — the sender did not include their public key. Get it from a keyserver or import the .asc file via the Keys page.")
    }

    function _retryPendingKey() {
        if (page._pendingKeyIndex < 0) return
        var url = ("" + message.attachmentModel.url(page._pendingKeyIndex))
        if (url === "") return
        var idx = page._pendingKeyIndex
        page._pendingKeyIndex = -1
        Gpg.inspectKeyFileForImport(url.indexOf("file://") === 0 ? url.substring(7) : url,
                                    "" + message.fromAddress)
    }

    // Build the header view from the ALREADY-LOADED EmailMessage properties.
    // IMPORTANT: do NOT call into the plugin to load the message again — loading
    // a QMailMessage in the plugin (as Gpg.messageHeaders did) triggers a QMF
    // re-render storm that freezes the app. These QML properties are free.
    function _encName(s) {
        switch (s) {
        case EmailMessage.NoDigitalEncryption: return "none"
        case EmailMessage.Encrypted: return "encrypted (PGP/MIME)"
        case EmailMessage.Decrypting: return "decrypting"
        case EmailMessage.DecryptionFailure: return "decryption failed"
        default: return "" + s
        }
    }
    function _sigName(s) {
        switch (s) {
        case EmailMessage.NoDigitalSignature: return "none"
        case EmailMessage.SignedValid: return "valid"
        case EmailMessage.SignedInvalid: return "INVALID"
        case EmailMessage.SignedExpired: return "expired key"
        case EmailMessage.SignedMissing: return "public key missing"
        case EmailMessage.SignedFailure: return "check failed"
        case EmailMessage.SignedUnchecked: return "unchecked"
        default: return "" + s
        }
    }
    function _headerText() {
        var L = []
        L.push("From: " + (message.fromDisplayName !== "" ? message.fromDisplayName + " " : "")
               + "<" + message.fromAddress + ">")
        if (message.to && message.to.length > 0) L.push("To: " + message.to.join(", "))
        if (message.cc && message.cc.length > 0) L.push("Cc: " + message.cc.join(", "))
        if (message.bcc && message.bcc.length > 0) L.push("Bcc: " + message.bcc.join(", "))
        if (message.replyTo && ("" + message.replyTo) !== "") L.push("Reply-To: " + message.replyTo)
        L.push("Subject: " + message.subject)
        L.push("Date: " + Format.formatDate(message.date, Formatter.Timepoint))
        if (message.inReplyTo && ("" + message.inReplyTo) !== "") L.push("In-Reply-To: " + message.inReplyTo)
        L.push("Attachments: " + message.numberOfAttachments)
        L.push("Size: " + message.size + " bytes")

        // Encryption: native PGP/MIME, or an inline ciphertext block, else none.
        var enc = message.encryptionStatus === EmailMessage.Encrypted ? "PGP/MIME"
                  : page._bodyHasPgp ? "inline PGP" : "none"
        L.push("Encryption: " + enc)

        // Signature: only known AFTER decryption for encrypted mails.
        var sig
        if (page._isDecrypted) {
            sig = page._sigResult !== "" ? page._sigResult : "none"
        } else if (page._isEncrypted) {
            sig = "decrypt first"
        } else if (page._bodyHasSignedBlock) {
            sig = "inline PGP signature — verify first"
        } else if (page._hasNativeSig) {
            sig = _sigName(message.signatureStatus)
        } else {
            sig = "none"
        }
        L.push("Signature: " + sig)
        return L.join("\n")
    }

    function signatureText() {
        // After our own decryption we know the real signature state.
        if (page._isDecrypted) return page._sigResult   // "" when unsigned
        // Encrypted but not yet decrypted: the signature is inside the ciphertext.
        if (page._isEncrypted) return qsTr("Signature: decrypt first")
        // Native signature — only the meaningful states (ignore QMF's bogus
        // Failure/Unchecked on plain unsigned mails).
        switch (message.signatureStatus) {
        case EmailMessage.SignedValid:   return qsTr("Valid signature")
        case EmailMessage.SignedInvalid: return qsTr("INVALID signature")
        case EmailMessage.SignedExpired: return qsTr("Signature from expired key")
        case EmailMessage.SignedMissing: return qsTr("Public key missing — cannot verify")
        default: return ""
        }
    }
    function signatureColor() {
        if (page._isDecrypted)
            return page._sigResult.indexOf("Good signature") >= 0 ? "#4caf50"
                   : page._sigResult.indexOf("BAD") >= 0 ? "#ff6b6b" : Theme.secondaryColor
        switch (message.signatureStatus) {
        case EmailMessage.SignedValid:   return "#4caf50"
        case EmailMessage.SignedInvalid: return "#ff6b6b"
        default: return Theme.secondaryColor
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            // NB: Reply and Delete are deliberately swapped vs. the usual order
            // (Delete on top, Reply at the bottom) — per user preference.
            MenuItem {
                text: qsTr("Delete")
                onClicked: {
                    // Just the remorse timer (with undo) — the extra confirm dialog
                    // was one tap too many.
                    var mid = page.messageId
                    remorsePopup.execute(qsTr("Deleting message"),
                                         function() { emailAgent.deleteMessage(mid); pageStack.pop() })
                }
            }
            MenuItem {
                text: qsTr("Show header")
                onClicked: pageStack.push(Qt.resolvedUrl("HeaderPage.qml"),
                                          { messageId: page.messageId })
            }
            MenuItem {
                text: qsTr("Encryption info")
                onClicked: {
                    if (page._smimeKind !== "") {
                        // S/MIME → show S/MIME certs (NOT PGP). No passphrase prompt:
                        // recipient certs + CA chains need none, and the signature
                        // certs are taken from an earlier decrypt of this message
                        // (like PGP, where decrypting once is enough).
                        pageStack.push(Qt.resolvedUrl("SmimeInfoPage.qml"),
                                       { info: Smime.messageCertInfo(page.messageId, "") })
                    } else if (message.encryptionStatus === EmailMessage.Encrypted) {
                        page._ensureEncPart("inspect", "")        // PGP/MIME (lädt Teil ggf. nach)
                    } else if (page._bodyHasPgp) {
                        pageStack.push(Qt.resolvedUrl("CryptoInfoPage.qml"),
                                       { info: Gpg.encryptionInfo(message.body),
                                         senderEmail: ("" + message.fromAddress),
                                         importKey: function() { return page._importKeyFromMessage() } })  // inline PGP
                    } else {
                        // Not encrypted at all.
                        pageStack.push(Qt.resolvedUrl("SmimeInfoPage.qml"),
                                       { info: { unencrypted: true, format: "Unencrypted" } })
                    }
                }
            }
            MenuItem {
                // Direct entry for importing a public key the sender attached/inlined
                // (works even when the mail is already decryptable, unlike the
                // "Encryption info" path which only surfaces MISSING recipient keys).
                visible: page._hasImportableKey
                text: qsTr("Import sender's key")
                onClicked: {
                    var r = page._importKeyFromMessage()
                    if (r && r.length > 0) page._topNotice = r   // "" → wait for dialog/importFinished
                }
            }
            MenuItem {
                // Resolve the chicken/egg: from an S/MIME mail, reach cert management
                // to install your own .p12 (needed to decrypt) or import certificates.
                visible: page._smimeKind !== ""
                text: qsTr("S/MIME certificates…")
                onClicked: pageStack.push(Qt.resolvedUrl("SmimeCertsPage.qml"))
            }
            MenuItem {
                text: qsTr("Download full message")
                onClicked: {
                    page._topNotice = qsTr("Downloading the full message…")
                    dlNoticeTimer.restart()
                    message.downloadMessage()
                }
            }
            MenuItem {
                text: qsTr("Reply")
                onClicked: {
                    // Match the reply's crypto to the RECEIVED mail: S/MIME mail →
                    // S/MIME reply; PGP mail → PGP (inline → inline, else MIME); plain
                    // → plain. The composer's type is fixed (no manual choice on reply).
                    var smime = page._smimeKind !== ""
                    var enc = smime || (message.encryptionStatus === EmailMessage.Encrypted) || page._bodyHasPgp
                    var fmt = (message.encryptionStatus === EmailMessage.Encrypted) ? "mime"
                              : (page._bodyHasPgp ? "inline" : "mime")
                    pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                   { replyTo: message.fromAddress,
                                     subjectPrefill: "Re: " + message.subject,
                                     encryptReply: enc, replyFormat: fmt,
                                     replyAccountId: message.accountId,
                                     cryptoKind: smime ? "smime" : "pgp",
                                     cryptoKindFixed: true })
                }
            }
        }

        RemorsePopup { id: remorsePopup }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: message.subject !== "" ? message.subject : qsTr("(no subject)")
            }

            // Transient info line (key import / download status).
            Label {
                visible: page._topNotice !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                text: page._topNotice
                color: Theme.highlightColor
                font.pixelSize: Theme.fontSizeSmall
            }

            Column {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    text: message.fromDisplayName !== "" ? message.fromDisplayName : message.fromAddress
                    color: Theme.highlightColor
                }
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: qsTr("to") + " " + (message.to ? message.to.join(", ") : "")
                }
                Label {
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: Format.formatDate(message.date, Formatter.Timepoint)
                }
            }

            // --- Krypto-Banner ---------------------------------------------
            Rectangle {
                visible: message.encryptionStatus !== EmailMessage.NoDigitalEncryption
                         || page._hasNativeSig || page.signatureText() !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                height: cryptoCol.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: Theme.rgba(Theme.highlightBackgroundColor, 0.15)

                Column {
                    id: cryptoCol
                    y: Theme.paddingMedium
                    x: Theme.paddingMedium
                    width: parent.width - 2 * Theme.paddingMedium
                    spacing: Theme.paddingSmall

                    Label {
                        visible: message.encryptionStatus !== EmailMessage.NoDigitalEncryption
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: message.encryptionStatus === EmailMessage.Encrypted ? qsTr("Encrypted message")
                              : message.encryptionStatus === EmailMessage.Decrypting ? qsTr("Decrypting…")
                              : message.encryptionStatus === EmailMessage.DecryptionFailure ? qsTr("Decryption failed")
                              : qsTr("Encrypted")
                        color: message.encryptionStatus === EmailMessage.DecryptionFailure ? "#ff6b6b" : Theme.primaryColor
                    }
                    Label {
                        visible: message.encryptionStatus !== EmailMessage.NoDigitalEncryption
                        width: parent.width
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        text: qsTr("Format: PGP/MIME")
                    }
                    Label {
                        visible: page.signatureText() !== ""
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: page.signatureText()
                              + (message.signingKeys && message.signingKeys.length > 0
                                 ? "  (" + message.signingKeys[0].slice(-8) + ")" : "")
                        color: page.signatureColor()
                    }
                    Button {
                        visible: message.encryptionStatus === EmailMessage.Encrypted && page._inlinePlain === ""
                        text: qsTr("Decrypt")
                        onClicked: page._decryptPrompt()
                    }
                }
            }

            // --- Inline-PGP-Banner (Body enthält einen PGP-Block) ----------
            Rectangle {
                visible: (page._bodyHasPgp || page._bodyHasSignedBlock)
                         && message.encryptionStatus === EmailMessage.NoDigitalEncryption
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                height: inlineCol.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: Theme.rgba(Theme.highlightBackgroundColor, 0.15)

                Column {
                    id: inlineCol
                    y: Theme.paddingMedium; x: Theme.paddingMedium
                    width: parent.width - 2 * Theme.paddingMedium
                    spacing: Theme.paddingSmall
                    Label {
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: page._inlineInfo !== "" ? page._inlineInfo
                              : page._bodyHasPgp ? qsTr("Inline PGP message")
                                                 : qsTr("Inline PGP signature")
                        color: Theme.primaryColor
                    }
                    Label {
                        width: parent.width
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        text: qsTr("Format: Inline PGP")
                    }
                    Button {
                        visible: page._inlinePlain === ""
                        text: page._bodyHasPgp ? qsTr("Decrypt") : qsTr("Verify")
                        onClicked: {
                            if (page._bodyHasPgp) {
                                var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                                         { info: qsTr("To decrypt this message") })
                                dlg.accepted.connect(function() { Gpg.decryptText(message.body, dlg.passphrase) })
                            } else {
                                Gpg.decryptText(message.body, "")  // signature only — no passphrase
                            }
                        }
                    }
                }
            }

            // --- S/MIME (PKI) banner ---------------------------------------
            Rectangle {
                visible: page._smimeKind !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                height: smimeCol.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: Theme.rgba(Theme.highlightBackgroundColor, 0.15)
                Column {
                    id: smimeCol
                    y: Theme.paddingMedium; x: Theme.paddingMedium
                    width: parent.width - 2 * Theme.paddingMedium
                    spacing: Theme.paddingSmall
                    Label {
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.primaryColor
                        text: page._smimeInfo !== "" ? page._smimeInfo
                              : page._smimeKind === "encrypted" ? qsTr("Encrypted S/MIME message")
                                                                : qsTr("Signed S/MIME message")
                    }
                    Label {
                        width: parent.width; font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        text: qsTr("Format: S/MIME (PKI)")
                    }
                    // Encrypted: decrypting also learns the sender's certificate.
                    Button {
                        visible: page._smimeKind === "encrypted" && page._smimePlain === ""
                        text: qsTr("Decrypt")
                        onClicked: {
                            var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                                     { info: qsTr("To decrypt this S/MIME message") })
                            dlg.accepted.connect(function() { Smime.decryptMessage(page.messageId, dlg.passphrase) })
                        }
                    }
                    // Only shown when the sender's cert is NOT yet in the store
                    // (checked on open for signed mails, after Decrypt for encrypted).
                    Button {
                        visible: page._smimeImportNeeded
                        text: qsTr("Import sender's certificate")
                        onClicked: {
                            // Encrypted mail → cert was stashed during Decrypt;
                            // signed mail → extract from the message now.
                            if (page._smimeKind === "encrypted") Smime.importPendingSenderCert()
                            else Smime.importCertFromMessage(page.messageId)
                        }
                    }
                }
            }

            // --- Body ------------------------------------------------------
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                textFormat: Text.PlainText
                text: page._smimePlain !== "" ? page._smimePlain
                      : page._inlinePlain !== "" ? page._inlinePlain
                      : message.body !== "" ? message.body
                      : qsTr("(empty — pull down to download)")
                color: Theme.primaryColor
                font.pixelSize: Theme.fontSizeSmall
            }

            // --- Großer-Anhang-Banner: interaktiv statt starrer Fehlermeldung ---
            Rectangle {
                visible: page._oversized
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                height: obCol.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: Qt.rgba(1, 0.65, 0, 0.12)
                Column {
                    id: obCol
                    x: Theme.paddingMedium
                    y: Theme.paddingMedium
                    width: parent.width - 2 * Theme.paddingMedium
                    spacing: Theme.paddingSmall
                    Label {
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.highlightColor
                        text: qsTr("Unusually large attachment detected. Expecting a larger e-mail? You can load it once without the size limit.")
                    }
                    Button {
                        text: qsTr("Load without limit (15 min)")
                        onClicked: {
                            Gpg.liftSizeLimit()
                            page._oversized = false
                            page._decryptPrompt()
                        }
                    }
                }
            }

            // --- Entschlüsselte PGP/MIME-Anhänge ---------------------------
            Column {
                visible: page._mimeAttachments.length > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                spacing: Theme.paddingSmall
                SectionHeader {
                    text: (message.encryptionStatus === EmailMessage.Encrypted
                           || page._bodyHasPgp || page._smimeKind !== "")
                          ? qsTr("Decrypted attachments (%1)").arg(page._mimeAttachments.length)
                          : qsTr("Attachments (%1)").arg(page._mimeAttachments.length)
                }
                Repeater {
                    model: page._mimeAttachments
                    delegate: Column {
                        width: parent.width
                        spacing: Theme.paddingSmall
                        // Inline-Vorschau für Bilder
                        Image {
                            visible: modelData.isImage
                            width: parent.width
                            fillMode: Image.PreserveAspectFit
                            asynchronous: true
                            source: modelData.isImage ? modelData.url : ""
                        }
                        ListItem {
                            id: decAtt
                            width: parent.width
                            contentHeight: Theme.itemSizeSmall
                            // This ListItem is NOT the delegate root (Column is), so
                            // child Label / ContextMenu must qualify with the id.
                            property string attUrl: "" + modelData.url
                            property string attSrc: modelData.path ? ("" + modelData.path) : ("" + modelData.url)
                            property string attName: "" + modelData.name
                            onClicked: openMenu()
                            menu: ContextMenu {
                                MenuItem {
                                    text: qsTr("Open with…")
                                    onClicked: Qt.openUrlExternally(decAtt.attUrl)
                                }
                                MenuItem {
                                    text: qsTr("Save as…")
                                    onClicked: page._saveAs(decAtt.attSrc, decAtt.attName)
                                }
                            }
                            Row {
                                x: Theme.paddingMedium
                                anchors.verticalCenter: parent.verticalCenter
                                width: parent.width - 2 * Theme.paddingMedium
                                spacing: Theme.paddingMedium
                                Label {
                                    width: parent.width - decSize.width - parent.spacing
                                    truncationMode: TruncationMode.Fade
                                    text: decAtt.attName
                                    font.pixelSize: Theme.fontSizeSmall
                                    color: Theme.highlightColor
                                }
                                Label {
                                    id: decSize
                                    text: page._fmtSize(modelData.size)
                                    font.pixelSize: Theme.fontSizeExtraSmall
                                    color: Theme.secondaryColor
                                    anchors.verticalCenter: parent.verticalCenter
                                }
                            }
                        }
                    }
                }
            }

            // --- Plain attachments on SFOS 5.x (native attachmentModel) ----
            Column {
                visible: !!message.attachmentModel && message.numberOfAttachments > 0
                         && page._mimeAttachments.length === 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                spacing: Theme.paddingSmall
                SectionHeader { text: qsTr("Attachments (%1)").arg(message.numberOfAttachments) }
                Repeater {
                    model: message.attachmentModel
                    delegate: ListItem {
                        id: pAtt
                        width: parent.width
                        contentHeight: Theme.itemSizeSmall
                        property bool _dl: ("" + model.url) !== ""
                        property string attUrl: "" + model.url
                        property string attName: "" + model.displayName
                        // NB: there is NO "location" role on AttachmentListModel, so
                        // "model.location" is undefined → "undefined" → passing that to
                        // downloadAttachment segfaults QMF (see comment above). Use the
                        // proven location(i) method (same one _ensureEncPart uses); the
                        // location is static metadata, so a one-shot binding is fine.
                        property string attLoc: "" + message.attachmentModel.location(index)
                        property string _pending: ""   // "open"|"save" once downloaded
                        // Start the on-demand download, guarding against an empty/bad
                        // location (QMF dereferences garbage on a malformed location).
                        function _startDownload(pending) {
                            if (attLoc === "" || attLoc === "undefined") {
                                page._topNotice = qsTr("Could not load the attachment")
                                return
                            }
                            pAtt._pending = pending
                            page._topNotice = qsTr("Downloading attachment…")
                            message.downloadAttachment(attLoc)
                        }
                        // The big attachment downloads on demand; finish the action
                        // the user picked once its file path arrives.
                        on_DlChanged: {
                            if (_dl && _pending !== "") {
                                if (_pending === "open") Qt.openUrlExternally(attUrl)
                                else if (_pending === "save") page._saveAs(attUrl, attName)
                                _pending = ""
                                page._topNotice = ""
                            }
                        }
                        onClicked: openMenu()
                        menu: ContextMenu {
                            MenuItem {
                                text: qsTr("Open with…")
                                onClicked: {
                                    if (pAtt._dl) Qt.openUrlExternally(pAtt.attUrl)
                                    else pAtt._startDownload("open")
                                }
                            }
                            MenuItem {
                                text: qsTr("Save as…")
                                onClicked: {
                                    if (pAtt._dl) page._saveAs(pAtt.attUrl, pAtt.attName)
                                    else pAtt._startDownload("save")
                                }
                            }
                        }
                        Row {
                            x: Theme.paddingMedium
                            anchors.verticalCenter: parent.verticalCenter
                            width: parent.width - 2 * Theme.paddingMedium
                            spacing: Theme.paddingMedium
                            Label {
                                width: parent.width - pSize.width - parent.spacing
                                truncationMode: TruncationMode.Fade
                                text: pAtt.attName
                                font.pixelSize: Theme.fontSizeSmall
                            }
                            Label {
                                id: pSize
                                text: page._fmtSize(model.size)
                                font.pixelSize: Theme.fontSizeExtraSmall
                                color: Theme.secondaryColor
                                anchors.verticalCenter: parent.verticalCenter
                            }
                        }
                    }
                }
            }

            // Fallback (SFOS 4.6 only): we couldn't parse the raw MIME yet (message
            // not fully downloaded) → tell the user how to load it.
            Column {
                visible: !message.attachmentModel && page._mimeAttachments.length === 0
                         && message.numberOfAttachments > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                SectionHeader { text: qsTr("Attachments (%1)").arg(message.numberOfAttachments) }
                Label {
                    width: parent.width
                    wrapMode: Text.WordWrap
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: qsTr("Pull down “Download full message” to load the attachment(s).")
                }
            }
        }
        VerticalScrollDecorator { }
    }
}
