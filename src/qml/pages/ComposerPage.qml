import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import Nemo.Email 0.1
import org.nemomobile.contacts 1.0
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
    // Filled in by a mailto: link / "share via email" arriving over
    // com.jolla.email.ui (see MailAccountsPage) — those carry more than a To:.
    property string bodyPrefill: ""
    property string ccPrefill: ""
    property string bccPrefill: ""
    // Reply context: pre-arm encryption and match the incoming format.
    property bool encryptReply: false
    property string replyFormat: "mime"     // "mime" | "inline"
    property int replyAccountId: 0          // account the original mail belongs to
    property int composeAccountId: 0        // mailbox we're composing from (new mail)
    property int fromTemplateId: 0          // >0 → prefill from a saved template
    property int fromDraftId: 0             // >0 → editing a saved draft (replace on send/save)
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
        var from = page._fromAddr()
        // Start from what the SENDER can do; encryption additionally needs every
        // recipient to have a key/cert in that method. Sign-only needs no recipients.
        var pgp = _senderHasPgp(from)
        var sm  = _senderHasSmime(from)
        if (encryptSwitch.checked) {
            var addrs = _recipsByKind("to").concat(_recipsByKind("cc")).concat(_bccList())
            if (addrs.length === 0) { pgp = false; sm = false }
            else for (var i = 0; i < addrs.length; ++i) {
                // Only a usable key counts — a revoked or signing-only key must
                // not make PGP look possible here.
                if (pgp && _usableKeys(Gpg.publicKeys(addrs[i])).length === 0) pgp = false
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
                // The dialog was given open recipients first, blind ones last, so
                // the tail of its answer belongs to the blind copies.
                var split = c.fprs.length - c.blindCount
                var blind = []
                for (var i = split; i < c.fprs.length; ++i)
                    blind.push({ address: c.addrs[i], fprs: [c.fprs[i]] })
                page._continueSend(c.addrs.slice(0, split), [], c.fprs.slice(0, split), blind)
            }
        }
    }

    // Stash for the async inline-encrypt → send path.
    property var _inlineTo: []
    property var _inlineCc: []
    property var _inlineBcc: []

    EmailAccountListModel { id: accountsModel }
    // Sending identities: every account address, followed by the alias
    // addresses the system's account settings hold for it. We read the very
    // setting those settings write, so our list and the platform's are one
    // list. An alias is a full sender: it goes into the From header, and the
    // key/certificate lookup follows it — so an alias without its own key
    // simply cannot sign, which is the truth rather than a signature in
    // somebody else's name.
    ListModel { id: identities }        // {accountId, address, alias}
    // This model has no countChanged; it announces itself through these.
    Connections {
        target: accountsModel
        onModelReset: page._buildIdentities()
        onAccountsAdded: page._buildIdentities()
        onAccountsRemoved: page._buildIdentities()
        onAccountsUpdated: page._buildIdentities()
    }
    function _buildIdentities() {
        var keepAcct = page._acctId()
        var keepAddr = page._fromAddr()
        identities.clear()
        for (var i = 0; i < accountsModel.count; ++i) {
            var addr = "" + accountsModel.emailAddress(i)
            var id = accountsModel.accountId(i)
            identities.append({ "accountId": id, "address": addr, "alias": "" })
            var aliases = Gpg.accountAliases(addr)
            for (var j = 0; j < aliases.length; ++j)
                identities.append({ "accountId": id, "address": "" + aliases[j],
                                    "alias": "" + aliases[j] })
        }
        // Keep the user's pick across a rebuild.
        if (keepAddr !== "") {
            for (var k = 0; k < identities.count; ++k) {
                var e = identities.get(k)
                if (e.accountId === keepAcct && e.address === keepAddr) {
                    accountCombo.currentIndex = k
                    return
                }
            }
        }
    }
    function _identity() {
        var i = accountCombo.currentIndex
        return (i >= 0 && i < identities.count) ? identities.get(i) : null
    }
    function _acctId()   { var d = page._identity(); return d ? d.accountId : 0 }
    function _fromAddr() { var d = page._identity(); return d ? ("" + d.address) : "" }
    function _fromAlias(){ var d = page._identity(); return d ? ("" + d.alias) : "" }
    // First identity of an account = the account's own address, not an alias.
    function _identityIndexForAccount(acct) {
        for (var i = 0; i < identities.count; ++i)
            if (identities.get(i).accountId === acct) return i
        return -1
    }
    EmailMessage { id: outgoing }
    ListModel { id: attModel }   // {name, path, mimeType}
    // Dynamic recipient rows: {kind: "to"|"cc"|"bcc", addr}. Starts with one To row;
    // the "+" button adds more (To/Cc/Bcc) via a small dropdown.
    ListModel { id: recipModel; ListElement { kind: "to"; addr: "" } }

    function _addRecip(kind) { recipModel.append({ kind: kind, addr: "" }) }

    // --- Suggestions while typing a recipient -------------------------------
    // Source: the addresses the user remembered, then the address book. Built
    // once into a flat array; matching then happens in memory, per keystroke.
    // Nothing here may touch gpg/gpgsm — the key hint deliberately runs only
    // when a field is left, because each of those calls starts a process.
    property var _addrPool: []
    PeopleModel {
        id: people
        filterType: PeopleModel.FilterAll
        requiredProperty: PeopleModel.EmailAddressRequired
        onPopulatedChanged: poolTimer.restart()
        onCountChanged: poolTimer.restart()
    }
    Timer { id: poolTimer; interval: 150; onTriggered: page._buildAddrPool() }
    function _buildAddrPool() {
        var pool = []
        var seen = {}
        function addPool(addr, name, remembered) {
            var a = ("" + addr).trim()
            if (a.indexOf("@") < 1) return
            var low = a.toLowerCase()
            if (seen[low]) return           // first source wins, see the order below
            seen[low] = true
            pool.push({ "name": (name === undefined || name === null) ? "" : ("" + name),
                        "address": a, "remembered": !!remembered })
        }

        // Order matters: what the user remembered on purpose comes first, then
        // everyone we hold a key or certificate for (addresses already worked
        // with, and often not in the address book at all), then the address
        // book itself.
        var mine = Gpg.rememberedAddresses()
        for (var m = 0; m < mine.length; ++m)
            addPool(mine[m].address, mine[m].name, true)

        var keys = Gpg.publicKeys()
        for (var k = 0; k < keys.length; ++k) {
            var ka = keys[k].emails
            if (ka && ka.length > 0) {
                for (var ke = 0; ke < ka.length; ++ke) addPool(ka[ke], keys[k].name, false)
            } else {
                addPool(keys[k].email, keys[k].name, false)
            }
        }
        if (Gpg.smimeEnabled && Smime.available) {
            var certs = Smime.listCerts()
            for (var ci = 0; ci < certs.length; ++ci) {
                var ce = certs[ci].emails
                for (var cj = 0; ce && cj < ce.length; ++cj) addPool(ce[cj], certs[ci].uid, false)
            }
        }

        for (var i = 0; i < people.count; ++i) {
            var c = people.get(i)
            if (!c) continue
            var details = c.emailDetails
            if (!details) continue
            for (var j = 0; j < details.length; ++j)
                addPool(details[j].address, c.displayLabel, false)
        }
        page._addrPool = pool
    }
    // The field may already hold "a@b.c, " — only the part after the last comma
    // is being typed, and only that part gets replaced when a suggestion is
    // tapped.
    function _typedFragment(text) {
        var t = "" + text
        var i = t.lastIndexOf(",")
        return (i < 0 ? t : t.substring(i + 1)).replace(/^\s+/, "")
    }
    function _withFragment(text, address) {
        var t = "" + text
        var i = t.lastIndexOf(",")
        return (i < 0 ? "" : t.substring(0, i + 1) + " ") + address
    }
    function _suggest(text) {
        var q = page._typedFragment(text).toLowerCase()
        if (q.length < 2) return []
        var hits = []
        for (var i = 0; i < page._addrPool.length && hits.length < 6; ++i) {
            var e = page._addrPool[i]
            var a = ("" + e.address).toLowerCase()
            if (a === q) continue                       // already typed in full
            if (a.indexOf(q) >= 0 || ("" + e.name).toLowerCase().indexOf(q) >= 0) {
                var dup = false
                for (var d = 0; d < hits.length; ++d)
                    if (("" + hits[d].address).toLowerCase() === a) { dup = true; break }
                if (!dup) hits.push(e)
            }
        }
        return hits
    }

    Component.onCompleted: {
        // Pick the sending account: reply → the original mail's account; new mail
        // from a mailbox → that mailbox; otherwise the user's chosen default.
        var acct = replyAccountId > 0 ? replyAccountId
                 : composeAccountId > 0 ? composeAccountId
                 : Gpg.defaultAccountId()
        page._buildIdentities()
        var idx = acct > 0 ? page._identityIndexForAccount(acct) : -1
        if (idx >= 0) accountCombo.currentIndex = idx
        if (("" + replyTo) !== "") recipModel.setProperty(0, "addr", "" + replyTo)
        if (("" + ccPrefill) !== "") recipModel.append({ kind: "cc", addr: "" + ccPrefill })
        if (("" + bccPrefill) !== "") recipModel.append({ kind: "bcc", addr: "" + bccPrefill })
        if (encryptReply) {
            encryptSwitch.checked = true
            formatCombo.currentIndex = (replyFormat === "inline") ? 1 : 0
            // S/MIME reply: also sign, matching how the received mail was protected.
            if (page.cryptoKind === "smime") signSwitch.checked = true
        }
        if (fromTemplateId > 0) page._loadTemplate(fromTemplateId)
        // A draft prefills the same way (templateInfo reads any stored message).
        // It is REPLACED (old copy removed) when sent or re-saved — see
        // _closeComposer(); a plain back-swipe leaves the draft untouched.
        else if (fromDraftId > 0) page._loadTemplate(fromDraftId)
    }

    // Prefill the composer from a saved template. The template stays untouched in
    // the Templates folder (it is only read here) — reuse it as often as you like.
    function _loadTemplate(id) {
        var t = Gpg.templateInfo(id)
        if (!t) return
        subjectField.text = ("" + (t.subject || ""))
        bodyField.text = ("" + (t.body || ""))
        // Rebuild the recipient rows from the template.
        recipModel.clear()
        var kinds = [["to", t.to], ["cc", t.cc], ["bcc", t.bcc]]
        for (var k = 0; k < kinds.length; ++k) {
            var list = kinds[k][1] || []
            for (var i = 0; i < list.length; ++i)
                recipModel.append({ kind: kinds[k][0], addr: "" + list[i] })
        }
        if (recipModel.count === 0) recipModel.append({ kind: "to", addr: "" })
        // Restore the crypto choice.
        if (("" + (t.cryptoKind || "")) !== "" && !page.cryptoKindFixed)
            page.cryptoKind = "" + t.cryptoKind
        if (t.encrypt) encryptSwitch.checked = true
        if (t.sign) signSwitch.checked = true
        page._recomputeCrypto()
    }

    // Save the current message as a reusable template (stays in the Templates
    // folder until actively deleted; not consumed on use, unlike a draft).
    function _saveTemplate() {
        if (page._acctId() <= 0) { status.text = qsTr("Choose an account"); status.error = true; return }
        var acct = page._acctId()
        var id = Gpg.saveTemplate(acct, subjectField.text,
                                  _recipsByKind("to"), _recipsByKind("cc"), _bccList(),
                                  bodyField.text, page.cryptoKind,
                                  encryptSwitch.checked, signSwitch.checked)
        status.error = (id === 0)
        status.text = (id > 0) ? qsTr("Saved as template") : qsTr("Could not save the template")
    }

    // Close the composer reliably. The send often completes WHILE the passphrase
    // dialog is still animating its own close — popping during that transition is
    // swallowed and the composer stays open. So wait until the page stack is idle,
    // then pop the composer (lands back on the page we came from).
    function _closeComposer() {
        // Only send/save success reaches here (a plain back-swipe does not). So if
        // we were editing a draft, the message just left the composer for good —
        // remove the old draft copy so it isn't left behind as a duplicate.
        if (page.fromDraftId > 0) { Gpg.deleteDraft(page.fromDraftId); page.fromDraftId = 0 }
        closeTimer.ticks = 0; closeTimer.start()
    }
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
        if (page._acctId() <= 0) { status.text = qsTr("Choose an account"); status.error = true; return }
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
            // Blind copies included: they get their own encrypted message, which
            // needs their certificate just like an open recipient's.
            var all = to.concat(cc).concat(_bccList())
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
        busy.running = true; page._sending = true
        status.error = false; status.text = qsTr("S/MIME — sending…")
        Smime.sendSmime(page._acctId(),
                        subjectField.text, to, cc, _bccList(),
                        bodyField.text, _attachmentArray(), enc, sign, passphrase,
                        page._fromAlias())
    }

    function _sendPlain(to, cc) {
        outgoing.from = page._fromAddr()
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
        if (page._acctId() <= 0) { status.text = qsTr("Choose an account"); status.error = true; return }
        var acct = page._acctId()
        // Save via the plugin (self-built RFC2822 + heap), NOT the native
        // EmailMessage.saveDraft(): the native incremental-QMF path intermittently
        // crashed on POP3 on the first save (same class the send/template paths
        // avoid). Attachments aren't kept in a draft (like templates) — recipients,
        // subject, body and the crypto choice are.
        var id = Gpg.saveDraft(acct, subjectField.text,
                               _recipsByKind("to"), _recipsByKind("cc"), _bccList(),
                               bodyField.text, page.cryptoKind,
                               encryptSwitch.checked, signSwitch.checked)
        if (id === 0) { status.text = qsTr("Could not save the draft"); status.error = true; return }
        // _closeComposer removes the old draft when we were editing one.
        _closeComposer()
    }

    // Usable = neither revoked nor expired AND able to encrypt. We NEVER encrypt
    // to a revoked/expired key, and a signing-only key would only fail later
    // inside the encrypt job — neither counts toward "ambiguous".
    function _usableKeys(keys) {
        return keys.filter(function(k){ return !k.revoked && !k.expired && k.canEncrypt })
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

    // Blind copies need their own keys: they get a message of their own, encrypted
    // only to them (a shared ciphertext would name every recipient key in the
    // clear). Before this they were left out of the key resolution entirely — the
    // blind recipient received a mail encrypted to To/Cc that they could not read.
    function _sendEncrypted(to, cc) {
        var openRecips = _resolveRecipients(to.concat(cc))
        var blindRecips = _resolveRecipients(_bccList())
        if (_needsReview(openRecips.concat(blindRecips))) {
            // Let the user pick the right key (and fix the address) per recipient.
            // Order matters: open recipients first, blind ones last (see the timer).
            var dlg = pageStack.push(Qt.resolvedUrl("KeySelectDialog.qml"),
                                     { recipients: openRecips.concat(blindRecips) })
            dlg.accepted.connect(function() {
                // Defer: wait for this dialog to finish popping before pushing the
                // passphrase dialog (see keySelDeferTimer).
                page._keySelChoice = { addrs: dlg.chosenAddresses, fprs: dlg.chosenFingerprints,
                                       blindCount: blindRecips.length }
                keySelDeferTimer.restart()
            })
            return
        }
        // Each recipient has exactly one usable key here (else we'd be reviewing).
        var fprs = openRecips.map(function(r){ return r.usable[0].fingerprint })
        var blind = blindRecips.map(function(r){
            return { address: r.address, fprs: [r.usable[0].fingerprint] }
        })
        page._continueSend(to, cc, fprs, blind)
    }

    // The sending account's own usable signing key (filtered by from-address, never
    // a foreign key, revoked/expired skipped). Returns "" and sets the status on
    // failure. Always work via the from-address + fingerprint, never an index into
    // the whole keyring.
    function _resolveSignKey() {
        var from = page._fromAddr()
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
        busy.running = true; page._sending = true
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
            Gpg.signPgpMime(page._acctId(),
                            subjectField.text, to, cc, bcc,
                            bodyField.text, _attachmentArray(),
                            signFpr, passphrase, page._fromAlias())  // → onSendFinished
        }
    }

    function _continueSend(to, cc, fprs, blind) {
        blind = blind || []
        // A mail addressed ONLY to blind copies has no open recipients and thus no
        // open key list — that is not a missing key.
        if ((fprs.length === 0 && blind.length === 0) || fprs.indexOf("") >= 0) {
            status.text = qsTr("Missing a key for one or more recipients."); status.error = true; return
        }
        for (var b = 0; b < blind.length; ++b) {
            if (!blind[b].fprs || blind[b].fprs.length === 0 || blind[b].fprs[0] === "") {
                status.text = qsTr("Missing a key for one or more recipients."); status.error = true; return
            }
        }
        var signFpr = ""
        if (signSwitch.checked) {
            signFpr = _resolveSignKey()   // per-account key, by fingerprint, never index [0]
            if (signFpr === "") return
        }
        if (signFpr !== "") {
            var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                     { info: qsTr("To sign the message") })
            dlg.accepted.connect(function() { page._dispatch(to, cc, fprs, blind, signFpr, dlg.passphrase) })
        } else {
            page._dispatch(to, cc, fprs, blind, "", "")
        }
    }

    // "Encrypt to self": also encrypt to the sending account's own key so the
    // sender can read their own copy (Sent folder) later — like other clients do.
    // Among the account's usable keys, one we hold the SECRET key for is
    // preferred: only that one can actually decrypt the Sent copy (a public key
    // imported for our own address must not win over our real identity).
    function _withSelfKey(fprs) {
        var from = page._fromAddr()
        if (("" + from) === "") return fprs
        var keys = Gpg.publicKeys(from)
        var selfFpr = ""
        for (var i = 0; i < keys.length; ++i) {
            var k = keys[i]
            if (k.revoked || k.expired || !k.canEncrypt) continue
            if (k.hasSecret) { selfFpr = k.fingerprint; break }
            if (selfFpr === "") selfFpr = k.fingerprint
        }
        if (selfFpr === "") return fprs
        var out = fprs.slice()
        if (out.indexOf(selfFpr) < 0) out.push(selfFpr)
        return out
    }

    function _dispatch(to, cc, fprs, blind, signFpr, passphrase) {
        blind = blind || []
        fprs = _withSelfKey(fprs)
        // Every blind copy is also encrypted to the sender's own key, so the copy
        // in Sent stays readable — same reason as _withSelfKey for the open copy.
        var blindCopies = blind.map(function(b){
            return { address: b.address, fprs: _withSelfKey(b.fprs) }
        })
        var bcc = _bccList()
        if (formatCombo.currentIndex === 1) {
            // Inline PGP — cannot encrypt attachments.
            if (attModel.count > 0) {
                status.text = qsTr("Inline PGP cannot encrypt attachments — use PGP/MIME.")
                status.error = true; return
            }
            // Inline PGP puts ONE armored block in the body and goes out as one
            // message, so a blind copy could only be served by encrypting it to
            // everyone at once — which would name every recipient key in the clear
            // and give the blind copy away. PGP/MIME sends a message per audience.
            if (bcc.length > 0) {
                status.text = qsTr("Inline PGP cannot hide blind copies — use PGP/MIME.")
                status.error = true; return
            }
            page._inlineTo = to; page._inlineCc = cc; page._inlineBcc = bcc
            busy.running = true; page._sending = true
            status.error = false; status.text = qsTr("Encrypting & sending…")
            Gpg.encrypt(fprs, bodyField.text, signFpr, passphrase)   // → onEncryptFinished
        } else {
            busy.running = true; page._sending = true
            status.error = false; status.text = qsTr("Encrypting & sending…")
            Gpg.sendPgpMime(page._acctId(),
                            subjectField.text, to, cc, blindCopies,
                            bodyField.text, _attachmentArray(),
                            fprs, signFpr, passphrase, page._fromAlias())
        }
    }

    // The engines are singletons: their send result reaches EVERY open composer.
    // Only the one that actually started a send may act on it — otherwise a second
    // composer (opened from a mailto: link or a share) would close the first and
    // delete its draft along the way.
    property bool _sending: false

    // S/MIME send result.
    Connections {
        target: Smime
        onSendFinished: {
            if (!page._sending) return
            page._sending = false
            busy.running = false
            if (ok) _closeComposer()
            else { status.text = qsTr("Send failed: %1").arg(error); status.error = true }
        }
    }

    Connections {
        target: Gpg
        // PGP/MIME path.
        onSendFinished: {
            if (!page._sending) return
            page._sending = false
            busy.running = false
            if (ok) _closeComposer()
            else { status.text = qsTr("Send failed: %1").arg(error); status.error = true }
        }
        // Inline path: encrypt produced the armored body → send it as plain text.
        onEncryptFinished: {
            if (!page._sending) return
            if (!ok) {
                page._sending = false
                busy.running = false
                status.text = qsTr("Encryption failed: %1").arg(error); status.error = true
                return
            }
            outgoing.from = page._fromAddr()
            outgoing.to = page._inlineTo
            outgoing.cc = page._inlineCc
            outgoing.bcc = page._inlineBcc
            outgoing.subject = subjectField.text
            outgoing.body = armored
            outgoing.send()
            page._sending = false
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
                // Unlike a draft, a template stays in the Templates folder and is
                // reused for composing without being consumed.
                text: qsTr("Save as template")
                enabled: !busy.running
                onClicked: page._saveTemplate()
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
                        model: identities
                        MenuItem { text: model.address }
                    }
                }
            }

            // --- Recipients: dynamic rows; the "+" adds To/Cc/Bcc -------------
            Repeater {
                model: recipModel
                delegate: Column {
                    id: recipRow
                    width: col.width
                    // The suggestion list below is a Repeater of its own, and
                    // its `index` shadows this one. Keep ours under a name that
                    // cannot be shadowed.
                    readonly property int _rowIndex: index
                    property string _hint: ""
                    property bool _hintOk: false
                    // Cross-check the address against our keys/certs (on focus-out or
                    // after picking — NOT per keystroke; each call spawns gpg/gpgsm).
                    function _updateHint(addr) {
                        var a = ("" + addr).replace(/\s/g, "")
                        if (a.indexOf("@") < 1 || a.lastIndexOf(".") < a.indexOf("@")) {
                            recipRow._hint = ""; recipRow._hintOk = false; return
                        }
                        var pgp = page._usableKeys(Gpg.publicKeys(a)).length > 0
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
                            onTextChanged: {
                                recipModel.setProperty(index, "addr", text)
                                suggestions.hits = page._suggest(text)
                            }
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
                                    suggestions.hits = []
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
                    // Suggestions from the remembered addresses and the address
                    // book. They appear while the field has focus and enough has
                    // been typed; tapping one replaces only the fragment being
                    // typed, so a second address can follow a comma.
                    Column {
                        id: suggestions
                        width: parent.width
                        property var hits: []
                        visible: recipField.activeFocus && hits.length > 0
                        Repeater {
                            model: suggestions.visible ? suggestions.hits : []
                            BackgroundItem {
                                width: suggestions.width
                                height: Theme.itemSizeSmall
                                onClicked: {
                                    var full = page._withFragment(recipField.text, "" + modelData.address)
                                    recipField.text = full
                                    recipModel.setProperty(recipRow._rowIndex, "addr", full)
                                    suggestions.hits = []
                                    recipRow._updateHint(full)
                                    page._recomputeCrypto()
                                }
                                Column {
                                    x: Theme.horizontalPageMargin
                                    width: parent.width - 2 * Theme.horizontalPageMargin
                                    anchors.verticalCenter: parent.verticalCenter
                                    Label {
                                        width: parent.width; truncationMode: TruncationMode.Fade
                                        font.pixelSize: Theme.fontSizeSmall
                                        color: modelData.remembered ? Theme.highlightColor : Theme.primaryColor
                                        text: ("" + modelData.name) !== "" ? modelData.name : modelData.address
                                    }
                                    Label {
                                        width: parent.width; truncationMode: TruncationMode.Fade
                                        font.pixelSize: Theme.fontSizeExtraSmall
                                        color: Theme.secondaryColor
                                        text: ("" + modelData.name) !== "" ? modelData.address : ""
                                        visible: text !== ""
                                    }
                                }
                            }
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
                text: page.bodyPrefill
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
