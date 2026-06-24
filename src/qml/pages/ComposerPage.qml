import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import Nemo.Email 0.1
import SFMail.Gpg 1.0

// Neue Nachricht verfassen und senden. Zwei Sende-Wege:
//   * Klartext  → Nemo.Email (EmailMessage.send), inkl. Anhänge.
//   * Verschlüsselt (PGP/MIME) → Gpg.sendPgpMime: Body + Anhänge werden als
//     inneres MIME zusammengebaut, als Ganzes verschlüsselt (optional signiert),
//     als multipart/encrypted (RFC 3156) verpackt und über QMF gesendet.
// PGP/MIME kann — anders als Inline-PGP — Anhänge/Bilder mitverschlüsseln.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property string replyTo: ""
    property string subjectPrefill: ""
    // Reply context: pre-arm encryption and match the incoming format.
    property bool encryptReply: false
    property string replyFormat: "mime"     // "mime" | "inline"
    property int replyAccountId: 0          // account the original mail belongs to
    property int composeAccountId: 0        // mailbox we're composing from (new mail)
    // Which crypto the Encrypt/Sign buttons use: "pgp" or "smime". A REPLY fixes it
    // to match the received mail (cryptoKindFixed=true); a NEW mail lets the user
    // pick (only when S/MIME is enabled — the rare both-available case).
    property string cryptoKind: "pgp"
    property bool cryptoKindFixed: false
    // What's actually possible for the CURRENT recipients: PGP needs a public key
    // for every recipient, S/MIME a certificate for every recipient. The PGP/S/MIME
    // picker only appears when BOTH are possible; otherwise the one that works is
    // auto-selected (so e.g. an S/MIME-only address never offers PGP). Recomputed on
    // recipient focus-out / pick / add-remove.
    property bool _pgpPossible: false
    property bool _smimePossible: false
    // Does the SENDER (From address) itself have a usable identity for each method?
    // This is the LEADING factor: S/MIME from an address with no own certificate is
    // impossible even if the recipient has one (you'd have nothing to sign/encrypt-
    // to-self with). Same for PGP and the sender's secret key.
    function _senderHasPgp(from) {
        var sec = Gpg.secretKeys(from)
        for (var i = 0; i < sec.length; ++i)
            if (!sec[i].revoked && !sec[i].expired) return true
        return false
    }
    function _senderHasSmime(from) {
        if (!Gpg.smimeEnabled || !Smime.available || from === "") return false
        var certs = Smime.listCerts()
        for (var i = 0; i < certs.length; ++i)
            if (certs[i].hasSecret && ("" + certs[i].uid).toLowerCase().indexOf(("" + from).toLowerCase()) >= 0)
                return true
        return false
    }
    function _recomputeCrypto() {
        var from = accountCombo.currentIndex >= 0 ? accountsModel.emailAddress(accountCombo.currentIndex) : ""
        // Start from what the SENDER can do; encryption additionally needs every
        // recipient to have a key/cert in that method. Sign-only needs no recipients.
        var pgp = _senderHasPgp(from)
        var sm  = _senderHasSmime(from)
        if (encryptSwitch.checked) {
            var addrs = _recipsByKind("to").concat(_recipsByKind("cc")).concat(_bccList())
            if (addrs.length === 0) { pgp = false; sm = false }
            else for (var i = 0; i < addrs.length; ++i) {
                if (pgp && Gpg.publicKeys(addrs[i]).length === 0) pgp = false
                if (sm && !Smime.hasCertFor(addrs[i])) sm = false
            }
        }
        page._pgpPossible = pgp
        page._smimePossible = sm
        if (!page.cryptoKindFixed) {           // new mail: auto-pick the only option
            if (sm && !pgp) page.cryptoKind = "smime"
            else if (pgp && !sm) page.cryptoKind = "pgp"
        }
    }

    // Deferred key-select choice — see _sendEncrypted/keySelDeferTimer below.
    property var _keySelChoice: null
    // After the key-select dialog is accepted we must NOT push the passphrase
    // dialog while the key-select dialog is still popping (push-during-pop leaves
    // it stuck in the stack → composer can't be closed). Wait until the composer
    // is the active page again, then continue.
    Timer {
        id: keySelDeferTimer
        property int ticks: 0
        interval: 60; repeat: true
        onRunningChanged: if (running) ticks = 0
        onTriggered: {
            ticks++
            if ((page.status === PageStatus.Active || ticks > 20) && _keySelChoice) {
                stop()
                var c = _keySelChoice; _keySelChoice = null
                page._continueSend(c.addrs, [], c.fprs)
            }
        }
    }

    // Stash for the async inline-encrypt → send path.
    property var _inlineTo: []
    property var _inlineCc: []
    property var _inlineBcc: []

    EmailAccountListModel { id: accountsModel }
    EmailMessage { id: outgoing }
    ListModel { id: attModel }   // {name, path, mimeType}
    // Dynamic recipient rows: {kind: "to"|"cc"|"bcc", addr}. Starts with one To row;
    // the "+" button adds more (To/Cc/Bcc) via a small dropdown.
    ListModel { id: recipModel; ListElement { kind: "to"; addr: "" } }

    function _addRecip(kind) { recipModel.append({ kind: kind, addr: "" }) }

    Component.onCompleted: {
        // Pick the sending account: reply → the original mail's account; new mail
        // from a mailbox → that mailbox; otherwise the user's chosen default.
        var acct = replyAccountId > 0 ? replyAccountId
                 : composeAccountId > 0 ? composeAccountId
                 : Gpg.defaultAccountId()
        var idx = acct > 0 ? accountsModel.indexFromAccountId(acct) : -1
        if (idx >= 0) accountCombo.currentIndex = idx
        if (("" + replyTo) !== "") recipModel.setProperty(0, "addr", "" + replyTo)
        if (encryptReply) {
            encryptSwitch.checked = true
            formatCombo.currentIndex = (replyFormat === "inline") ? 1 : 0
            // S/MIME reply: also sign, matching how the received mail was protected.
            if (page.cryptoKind === "smime") signSwitch.checked = true
        }
    }

    // Close the composer reliably. The send often completes WHILE the passphrase
    // dialog is still animating its own close — popping during that transition is
    // swallowed and the composer stays open. So wait until the page stack is idle,
    // then pop the composer (lands back on the page we came from).
    function _closeComposer() { closeTimer.ticks = 0; closeTimer.start() }
    Timer {
        id: closeTimer
        property int ticks: 0
        interval: 80; repeat: true
        onTriggered: {
            ticks++
            // Pop once the composer is the active page (single-dialog case) OR after
            // a short grace period. Compute the target NOW (composer is in the stack
            // here, so previousPage(page) is valid) and pop down to the page below
            // the composer — this removes the composer AND any leftover dialog in one
            // step, even when the composer is buried and never became active.
            if (page.status === PageStatus.Active || ticks > 8) {
                stop()
                var back = pageStack.previousPage(page)
                if (back) pageStack.pop(back)
                else pageStack.pop()
            }
        }
    }

    function _recipientList(field) {
        return field.split(/[,;]\s*/).map(function(s){ return s.trim() })
                    .filter(function(s){ return s !== "" })
    }

    // Collect all addresses of one kind ("to"/"cc"/"bcc") from the dynamic
    // recipient rows. Each row may itself hold several comma-separated addresses.
    function _recipsByKind(kind) {
        var out = []
        for (var i = 0; i < recipModel.count; ++i) {
            var r = recipModel.get(i)
            if (r.kind !== kind) continue
            var parts = _recipientList("" + r.addr)
            for (var j = 0; j < parts.length; ++j)
                if (out.indexOf(parts[j]) < 0) out.push(parts[j])
        }
        return out
    }

    // Bcc recipients come solely from the explicit Bcc rows (add one via "+" → Bcc;
    // to keep a copy for your other devices, just Bcc your own address).
    function _bccList() {
        return _recipsByKind("bcc")
    }

    function _attachmentArray() {
        var a = []
        for (var i = 0; i < attModel.count; ++i) {
            var it = attModel.get(i)
            a.push({ name: it.name, path: it.path, mimeType: it.mimeType })
        }
        return a
    }

    function _send() {
        status.text = ""
        if (accountCombo.currentIndex < 0) { status.text = qsTr("Choose an account"); status.error = true; return }
        var to = _recipsByKind("to")
        var cc = _recipsByKind("cc")
        // At least one real recipient somewhere (To/Cc/Bcc or the self-Bcc).
        if (to.length + cc.length + _bccList().length === 0) {
            status.text = qsTr("Enter recipients first"); status.error = true; return
        }

        // S/MIME path (when this is an S/MIME reply or the user picked S/MIME).
        if (page.cryptoKind === "smime" && (encryptSwitch.checked || signSwitch.checked)) {
            _sendSmime(to, cc); return
        }
        if (encryptSwitch.checked) _sendEncrypted(to, cc)        // sign embedded if also signing
        else if (signSwitch.checked) _sendSignedOnly(to, cc)     // sign, no encryption
        else _sendPlain(to, cc)
    }

    // S/MIME send: verify recipient certs (for encryption), ask the passphrase when
    // signing, then hand off to the engine (CMS → pkcs7-mime → outbox).
    function _sendSmime(to, cc) {
        if (encryptSwitch.checked) {
            var all = to.concat(cc)
            for (var i = 0; i < all.length; ++i) {
                if (!Smime.hasCertFor(all[i])) {
                    status.text = qsTr("No S/MIME certificate for %1 — open a signed mail from them and import it.").arg(all[i])
                    status.error = true; return
                }
            }
        }
        var enc = encryptSwitch.checked, sign = signSwitch.checked
        if (sign) {
            var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"), { info: qsTr("To sign the message") })
            dlg.accepted.connect(function() { page._dispatchSmime(to, cc, enc, true, dlg.passphrase) })
        } else {
            page._dispatchSmime(to, cc, enc, false, "")
        }
    }
    function _dispatchSmime(to, cc, enc, sign, passphrase) {
        busy.running = true
        status.error = false; status.text = qsTr("S/MIME — sending…")
        Smime.sendSmime(accountsModel.accountId(accountCombo.currentIndex),
                        subjectField.text, to, cc, _bccList(),
                        bodyField.text, _attachmentArray(), enc, sign, passphrase)
    }

    function _sendPlain(to, cc) {
        outgoing.from = accountsModel.emailAddress(accountCombo.currentIndex)
        outgoing.to = to
        outgoing.cc = cc
        outgoing.bcc = _bccList()
        outgoing.subject = subjectField.text
        outgoing.body = bodyField.text
        var paths = []
        for (var i = 0; i < attModel.count; ++i) paths.push(attModel.get(i).path)
        if (paths.length > 0) outgoing.attachments = paths
        outgoing.send()
        _closeComposer()
    }

    // Save the current (plaintext) message to Drafts — so nothing is lost when you
    // leave the composer (text could otherwise be lost). Encryption happens at send;
    // the draft keeps the editable plaintext.
    function _saveDraft() {
        if (accountCombo.currentIndex < 0) { status.text = qsTr("Choose an account"); status.error = true; return }
        outgoing.from = accountsModel.emailAddress(accountCombo.currentIndex)
        outgoing.to = _recipsByKind("to")
        outgoing.cc = _recipsByKind("cc")
        outgoing.bcc = _bccList()
        outgoing.subject = subjectField.text
        outgoing.body = bodyField.text
        var paths = []
        for (var i = 0; i < attModel.count; ++i) paths.push(attModel.get(i).path)
        if (paths.length > 0) outgoing.attachments = paths
        outgoing.saveDraft()
        _closeComposer()
    }

    // Usable = neither revoked nor expired. We NEVER encrypt to a revoked/expired
    // key, so they don't count toward "ambiguous".
    function _usableKeys(keys) {
        return keys.filter(function(k){ return !k.revoked && !k.expired })
    }

    // Resolve candidate keys for each recipient. `keys` = all found (for the
    // review dialog), `usable` = only the valid ones (what we actually pick from).
    function _resolveRecipients(addresses) {
        var res = []
        for (var i = 0; i < addresses.length; ++i) {
            var all = Gpg.publicKeys(addresses[i])
            res.push({ address: addresses[i], keys: all, usable: _usableKeys(all) })
        }
        return res
    }

    // Ask the user ONLY when a recipient has no usable key (must pick/fix) or more
    // than one usable key (genuinely ambiguous — something's off). Exactly one
    // valid key — even if a revoked one also exists — is used silently.
    function _needsReview(recips) {
        for (var i = 0; i < recips.length; ++i)
            if (recips[i].usable.length !== 1) return true
        return false
    }

    function _sendEncrypted(to, cc) {
        var all = to.concat(cc)
        var recips = _resolveRecipients(all)
        if (_needsReview(recips)) {
            // Let the user pick the right key (and fix the address) per recipient.
            var dlg = pageStack.push(Qt.resolvedUrl("KeySelectDialog.qml"), { recipients: recips })
            dlg.accepted.connect(function() {
                // Defer: wait for this dialog to finish popping before pushing the
                // passphrase dialog (see keySelDeferTimer).
                page._keySelChoice = { addrs: dlg.chosenAddresses, fprs: dlg.chosenFingerprints }
                keySelDeferTimer.restart()
            })
            return
        }
        // Each recipient has exactly one usable key here (else we'd be reviewing).
        var fprs = recips.map(function(r){ return r.usable[0].fingerprint })
        page._continueSend(to, cc, fprs)
    }

    // The sending account's own usable signing key (filtered by from-address, never
    // a foreign key, revoked/expired skipped). Returns "" and sets the status on
    // failure. Always work via the from-address + fingerprint, never an index into
    // the whole keyring.
    function _resolveSignKey() {
        var from = accountsModel.emailAddress(accountCombo.currentIndex)
        var sec = Gpg.secretKeys(from)
        for (var i = 0; i < sec.length; ++i)
            if (!sec[i].revoked && !sec[i].expired) return sec[i].fingerprint
        status.text = qsTr("No usable signing key for %1").arg(from); status.error = true
        return ""
    }

    // Sign only, no encryption (multipart/signed or inline clearsign). No recipient
    // keys needed — anyone can read it; the signature proves the sender holds the key.
    function _sendSignedOnly(to, cc) {
        var signFpr = _resolveSignKey()
        if (signFpr === "") return
        var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                 { info: qsTr("To sign the message") })
        dlg.accepted.connect(function() { page._dispatchSign(to, cc, signFpr, dlg.passphrase) })
    }

    function _dispatchSign(to, cc, signFpr, passphrase) {
        var bcc = _bccList()
        busy.running = true
        status.error = false; status.text = qsTr("Signing & sending…")
        if (formatCombo.currentIndex === 1) {
            // Inline clearsign — text only.
            if (attModel.count > 0) {
                busy.running = false
                status.text = qsTr("Inline PGP cannot carry attachments — use PGP/MIME.")
                status.error = true; return
            }
            page._inlineTo = to; page._inlineCc = cc; page._inlineBcc = bcc
            Gpg.clearSign(bodyField.text, signFpr, passphrase)   // → onEncryptFinished
        } else {
            Gpg.signPgpMime(accountsModel.accountId(accountCombo.currentIndex),
                            subjectField.text, to, cc, bcc,
                            bodyField.text, _attachmentArray(),
                            signFpr, passphrase)                  // → onSendFinished
        }
    }

    function _continueSend(to, cc, fprs) {
        if (fprs.length === 0 || fprs.indexOf("") >= 0) {
            status.text = qsTr("Missing a key for one or more recipients."); status.error = true; return
        }
        var signFpr = ""
        if (signSwitch.checked) {
            signFpr = _resolveSignKey()   // per-account key, by fingerprint, never index [0]
            if (signFpr === "") return
        }
        if (signFpr !== "") {
            var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                     { info: qsTr("To sign the message") })
            dlg.accepted.connect(function() { page._dispatch(to, cc, fprs, signFpr, dlg.passphrase) })
        } else {
            page._dispatch(to, cc, fprs, "", "")
        }
    }

    // "Encrypt to self": also encrypt to the sending account's own key so the
    // sender can read their own copy (Sent folder) later — like Thunderbird does.
    // Returns fprs plus the sender's first usable (not revoked/expired) key.
    function _withSelfKey(fprs) {
        var from = accountsModel.emailAddress(accountCombo.currentIndex)
        if (("" + from) === "") return fprs
        var keys = Gpg.publicKeys(from)
        var selfFpr = ""
        for (var i = 0; i < keys.length; ++i)
            if (!keys[i].revoked && !keys[i].expired) { selfFpr = keys[i].fingerprint; break }
        if (selfFpr === "") return fprs
        var out = fprs.slice()
        if (out.indexOf(selfFpr) < 0) out.push(selfFpr)
        return out
    }

    function _dispatch(to, cc, fprs, signFpr, passphrase) {
        fprs = _withSelfKey(fprs)
        var bcc = _bccList()
        if (formatCombo.currentIndex === 1) {
            // Inline PGP — cannot encrypt attachments.
            if (attModel.count > 0) {
                status.text = qsTr("Inline PGP cannot encrypt attachments — use PGP/MIME.")
                status.error = true; return
            }
            page._inlineTo = to; page._inlineCc = cc; page._inlineBcc = bcc
            busy.running = true
            status.error = false; status.text = qsTr("Encrypting & sending…")
            Gpg.encrypt(fprs, bodyField.text, signFpr, passphrase)   // → onEncryptFinished
        } else {
            busy.running = true
            status.error = false; status.text = qsTr("Encrypting & sending…")
            Gpg.sendPgpMime(accountsModel.accountId(accountCombo.currentIndex),
                            subjectField.text, to, cc, bcc,
                            bodyField.text, _attachmentArray(),
                            fprs, signFpr, passphrase)
        }
    }

    // S/MIME send result.
    Connections {
        target: Smime
        onSendFinished: {
            busy.running = false
            if (ok) _closeComposer()
            else { status.text = qsTr("Send failed: %1").arg(error); status.error = true }
        }
    }

    Connections {
        target: Gpg
        // PGP/MIME path.
        onSendFinished: {
            busy.running = false
            if (ok) _closeComposer()
            else { status.text = qsTr("Send failed: %1").arg(error); status.error = true }
        }
        // Inline path: encrypt produced the armored body → send it as plain text.
        onEncryptFinished: {
            if (!ok) {
                busy.running = false
                status.text = qsTr("Encryption failed: %1").arg(error); status.error = true
                return
            }
            outgoing.from = accountsModel.emailAddress(accountCombo.currentIndex)
            outgoing.to = page._inlineTo
            outgoing.cc = page._inlineCc
            outgoing.bcc = page._inlineBcc
            outgoing.subject = subjectField.text
            outgoing.body = armored
            outgoing.send()
            busy.running = false
            _closeComposer()
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                text: encryptSwitch.checked ? qsTr("Encrypt & send")
                    : signSwitch.checked    ? qsTr("Sign & send")
                                            : qsTr("Send")
                enabled: !busy.running
                onClicked: page._send()
            }
            MenuItem {
                text: qsTr("Save as draft")
                enabled: !busy.running
                onClicked: page._saveDraft()
            }
            MenuItem {
                text: qsTr("Add attachment")
                onClicked: pageStack.push(filePickerComponent)
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingSmall

            PageHeader { title: qsTr("New message") }

            ComboBox {
                id: accountCombo
                width: parent.width
                label: qsTr("From")
                currentIndex: 0
                // The From address decides what the sender can do → re-evaluate.
                onCurrentIndexChanged: page._recomputeCrypto()
                menu: ContextMenu {
                    Repeater {
                        model: accountsModel
                        MenuItem { text: model.emailAddress }
                    }
                }
            }

            // --- Recipients: dynamic rows; the "+" adds To/Cc/Bcc -------------
            Repeater {
                model: recipModel
                delegate: Column {
                    id: recipRow
                    width: col.width
                    property string _hint: ""
                    property bool _hintOk: false
                    // Cross-check the address against our keys/certs (on focus-out or
                    // after picking — NOT per keystroke; each call spawns gpg/gpgsm).
                    function _updateHint(addr) {
                        var a = ("" + addr).replace(/\s/g, "")
                        if (a.indexOf("@") < 1 || a.lastIndexOf(".") < a.indexOf("@")) {
                            recipRow._hint = ""; recipRow._hintOk = false; return
                        }
                        var pgp = Gpg.publicKeys(a).length > 0
                        var sm  = Gpg.smimeEnabled && Smime.available && Smime.hasCertFor(a)
                        recipRow._hintOk = pgp || sm
                        recipRow._hint = pgp && sm ? qsTr("🔑 PGP key + 📜 S/MIME certificate")
                                       : pgp ? qsTr("🔑 PGP key available")
                                       : sm ? qsTr("📜 S/MIME certificate available")
                                       : qsTr("no key/certificate for this address")
                    }
                    Row {
                        width: parent.width
                        TextField {
                            id: recipField
                            width: parent.width - contactBtn.width - (removeRecipBtn.visible ? removeRecipBtn.width : 0)
                            label: model.kind === "to" ? qsTr("To")
                                 : model.kind === "cc" ? qsTr("Cc") : qsTr("Bcc")
                            text: model.addr
                            placeholderText: qsTr("name@example.com, …")
                            inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhEmailCharactersOnly
                            EnterKey.iconSource: "image://theme/icon-m-enter-next"
                            EnterKey.onClicked: focus = false
                            onTextChanged: recipModel.setProperty(index, "addr", text)
                            onActiveFocusChanged: if (!activeFocus) { recipRow._updateHint(text); page._recomputeCrypto() }
                        }
                        // "+" → address book (live search), fills this row.
                        IconButton {
                            id: contactBtn
                            anchors.verticalCenter: recipField.verticalCenter
                            icon.source: "image://theme/icon-m-add"
                            onClicked: {
                                var picker = pageStack.push(Qt.resolvedUrl("ContactPickerPage.qml"))
                                picker.picked.connect(function(email) {
                                    recipModel.setProperty(index, "addr", email)
                                    recipField.text = email
                                    recipRow._updateHint(email)
                                    page._recomputeCrypto()
                                })
                            }
                        }
                        IconButton {
                            id: removeRecipBtn
                            anchors.verticalCenter: recipField.verticalCenter
                            icon.source: "image://theme/icon-m-remove"
                            visible: recipModel.count > 1
                            onClicked: { recipModel.remove(index); page._recomputeCrypto() }
                        }
                    }
                    Label {
                        visible: recipRow._hint !== ""
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: recipRow._hintOk ? Theme.highlightColor : Theme.secondaryColor
                        text: recipRow._hint
                    }
                }
            }

            // "+ Add recipient" → tapping opens a native dropdown (To / Cc / Bcc).
            // A ComboBox IS the Silica dropdown primitive; a standalone ContextMenu
            // does not give a clean popup. currentIndex is reset to the neutral
            // first row after each pick so it stays an action menu, not a selection.
            ComboBox {
                id: addRecipCombo
                width: parent.width
                label: qsTr("＋ Add recipient")
                currentIndex: 0
                menu: ContextMenu {
                    MenuItem { text: qsTr("…") }
                    MenuItem { text: qsTr("To");  onClicked: { page._addRecip("to");  addRecipCombo.currentIndex = 0 } }
                    MenuItem { text: qsTr("Cc");  onClicked: { page._addRecip("cc");  addRecipCombo.currentIndex = 0 } }
                    MenuItem { text: qsTr("Bcc"); onClicked: { page._addRecip("bcc"); addRecipCombo.currentIndex = 0 } }
                }
            }

            TextField {
                id: subjectField
                width: parent.width
                label: qsTr("Subject")
                text: page.subjectPrefill
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: bodyField.focus = true
            }

            // Encrypt and Sign are independent — you can do either or both. Sign-only
            // (no encryption) sends a readable, verifiably-from-you message.
            Row {
                width: parent.width
                TextSwitch {
                    id: encryptSwitch
                    width: parent.width / 2
                    text: qsTr("Encrypt")
                    onCheckedChanged: page._recomputeCrypto()
                }
                TextSwitch {
                    id: signSwitch
                    width: parent.width / 2
                    text: qsTr("Sign")
                }
            }

            // Rare case: a NEW mail where BOTH PGP and S/MIME work for the recipients
            // — only then is there a real choice. Otherwise the possible one is auto-
            // selected (or neither, if we have no key/cert). A reply is fixed.
            ComboBox {
                id: cryptoCombo
                width: parent.width
                visible: !page.cryptoKindFixed && page._pgpPossible && page._smimePossible
                         && (encryptSwitch.checked || signSwitch.checked)
                label: qsTr("Encryption type")
                currentIndex: page.cryptoKind === "smime" ? 1 : 0
                menu: ContextMenu {
                    MenuItem { text: qsTr("OpenPGP"); onClicked: page.cryptoKind = "pgp" }
                    MenuItem { text: qsTr("S/MIME (PKI)"); onClicked: page.cryptoKind = "smime" }
                }
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                visible: encryptSwitch.checked || signSwitch.checked
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: encryptSwitch.checked
                      ? (signSwitch.checked ? qsTr("Encrypted to the recipients' keys and signed with your key.")
                                            : qsTr("Encrypted to the recipients' keys."))
                      : qsTr("Signed with your key — anyone can read it, the recipient can verify it is from you.")
            }

            ComboBox {
                id: formatCombo
                width: parent.width
                // PGP/MIME vs Inline applies to OpenPGP only — hidden for S/MIME.
                visible: (encryptSwitch.checked || signSwitch.checked) && page.cryptoKind === "pgp"
                label: qsTr("Format")
                currentIndex: 0
                menu: ContextMenu {
                    MenuItem { text: qsTr("PGP/MIME (with attachments)") }
                    MenuItem { text: qsTr("Inline PGP (text only)") }
                }
            }

            TextArea {
                id: bodyField
                width: parent.width
                label: qsTr("Message")
                placeholderText: qsTr("Write your message…")
            }

            // --- Anhänge ---------------------------------------------------
            Column {
                width: parent.width
                visible: attModel.count > 0
                SectionHeader { text: qsTr("Attachments (%1)").arg(attModel.count) }
                Repeater {
                    model: attModel
                    delegate: ListItem {
                        width: parent.width
                        menu: ContextMenu {
                            MenuItem {
                                text: qsTr("Remove")
                                onClicked: attModel.remove(index)
                            }
                        }
                        Label {
                            x: Theme.horizontalPageMargin
                            anchors.verticalCenter: parent.verticalCenter
                            width: parent.width - 2 * Theme.horizontalPageMargin
                            truncationMode: TruncationMode.Fade
                            text: model.name + "  ·  " + model.mimeType
                            font.pixelSize: Theme.fontSizeSmall
                        }
                    }
                }
            }

            Label {
                id: status
                property bool error: false
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                visible: text.length > 0
                font.pixelSize: Theme.fontSizeExtraSmall
                color: error ? "#ff6b6b" : Theme.highlightColor
            }

            // Send button at the BOTTOM too (usability): no scrolling
            // up + pulley hunting after writing.
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: !busy.running
                text: encryptSwitch.checked ? qsTr("Encrypt & send")
                    : signSwitch.checked    ? qsTr("Sign & send")
                                            : qsTr("Send")
                onClicked: page._send()
            }

            // NB: a running Sailfish BusyIndicator triggers a render/compositor
            // freeze on some devices — confirmed by isolation. We
            // use a plain bool + a status text instead of the animated spinner.
            QtObject { id: busy; property bool running: false }
        }
        VerticalScrollDecorator { }
    }

    // Anhang über den System-Content-Picker hinzufügen.
    function _addAttachment(filePath, fileName, mimeType) {
        var p = ("" + filePath)
        if (p.indexOf("file://") === 0) p = p.substring(7)
        var n = fileName ? ("" + fileName) : p.split('/').pop()
        attModel.append({ name: n, path: p,
                          mimeType: mimeType ? ("" + mimeType) : "application/octet-stream" })
    }

    Component {
        id: filePickerComponent
        FilePickerPage {
            allowedOrientations: defaultAllowedOrientations
            title: qsTr("Select attachment")
            onSelectedContentPropertiesChanged: {
                page._addAttachment(selectedContentProperties.filePath,
                                    selectedContentProperties.fileName,
                                    selectedContentProperties.mimeType)
            }
        }
    }
}
