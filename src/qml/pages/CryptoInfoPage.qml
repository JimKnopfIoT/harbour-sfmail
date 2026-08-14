import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0
import "RecipientRoles.js" as Roles

// Zeigt die Verschlüsselungs-Infos einer Mail strukturiert an: an welche
// Schlüssel sie verschlüsselt ist, mit voller Zertifikatsprüfung. Revoked/
// abgelaufen werden ROT hervorgehoben. info = Map aus Gpg.encryptionInfo().
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property var info: ({})
    property string title: qsTr("Encryption info")
    // Optional callback (set by MessagePage) to import the sender's key.
    property var importKey: null
    property string senderEmail: ""
    property string _notice: ""
    // Set when keys.openpgp.org has a DIFFERENT key for the sender's address than
    // the one this message used → offer to import it (importPendingKey()).
    // A keyserver candidate is pending the user's import decision.
    property bool _candidatePending: false
    property bool _candidateOk: false   // true = it IS the key the message used
    // Becomes true once a key was imported this session → clears "not verified".
    property bool _verified: false

    readonly property var _recips: (info && info.recipients) ? info.recipients : []

    // Addresses from To: and Cc: of the message being inspected (set by
    // MessagePage). Everything the ciphertext is encrypted to but that appears
    // in NEITHER of them is a blind copy — see RecipientRoles.js.
    property var visibleAddresses: []
    readonly property var _roles: Roles.rolesFor(_recips,
                                                 function(r) { return r.uids || [] },
                                                 function(r) { return r.inKeyring === true },
                                                 page.visibleAddresses, page.senderEmail)
    readonly property int _blindCount: Roles.countRole(_roles, "blind")
    readonly property int _unknownCount: Roles.countRole(_roles, "unknown")
    // Named blind recipients, for the summary at the top.
    readonly property string _blindWho: {
        var who = []
        for (var i = 0; i < _roles.length; ++i) {
            if (_roles[i] !== "blind") continue
            var uids = _recips[i].uids || []
            who.push(uids.length > 0 ? ("" + uids[0]) : ("0x" + _recips[i].keyId))
        }
        return who.join("\n")
    }

    // Addresses the message is ADDRESSED to but whose keys are not among the
    // recipients of THIS ciphertext. With one message per audience that is the
    // normal case — the others hold their own copy — and it is the first question
    // anyone asks when the key count is smaller than the recipient list. Stated
    // neutrally: we know they are not a recipient here, not why.
    readonly property string _addressedElsewhere: {
        var known = []
        for (var i = 0; i < _recips.length; ++i)
            known = known.concat(Roles.addressList(_recips[i].uids || []))
        var out = []
        var addressed = Roles.addressList(page.visibleAddresses)
        for (var j = 0; j < addressed.length; ++j)
            if (known.indexOf(addressed[j]) < 0 && out.indexOf(addressed[j]) < 0)
                out.push(addressed[j])
        return out.join(", ")
    }

    function _roleText(i) {
        switch (_roles[i]) {
        case "visible": return qsTr("Listed in To/Cc")
        case "sender":  return qsTr("The sender (copy to self)")
        case "blind":   return _recips[i].hasSecret ? qsTr("⚠ Blind copy — this is you")
                                                    : qsTr("⚠ Blind copy — in no header")
        default:        return qsTr("Cannot be named — key not in your keyring")
        }
    }
    function _roleColor(i) {
        switch (_roles[i]) {
        case "blind":   return "#ffa726"
        case "unknown": return Theme.secondaryColor
        default:        return Theme.primaryColor
        }
    }
    // True if at least one key shown here is NOT in the keyring → offer import.
    readonly property bool _anyMissing: {
        for (var i = 0; i < _recips.length; ++i)
            if (!_recips[i].inKeyring) return true
        return false
    }
    // Key-id of the first missing key, to look up on the keyserver.
    readonly property string _missingKeyId: {
        for (var i = 0; i < _recips.length; ++i)
            if (!_recips[i].inKeyring) return "" + _recips[i].keyId
        return ""
    }

    Connections {
        target: Gpg
        onImportFinished: {
            if (ok) page._verified = true
            page._notice = ok ? qsTr("Imported %1 key(s) into your keyring. Reopen Encryption info to refresh.").arg(imported)
                              : qsTr("Key import failed: %1").arg(error)
        }
        onKeyFetchStarted: { page._candidatePending = false; page._notice = qsTr("Searching keys.openpgp.org…") }
        onKeyFetchFinished: { page._candidatePending = false; if (ok) page._verified = true; page._notice = message }
        // A key was found on keys.openpgp.org — shown for the user to verify and
        // decide. We NEVER import automatically (security).
        onKeyCandidate: {
            page._candidatePending = true
            page._candidateOk = matchesUsedKey
            var who = "0x" + foundKeyId + (foundUids ? "  (" + foundUids + ")" : "")
            var fp = foundFpr ? "\nFingerprint: " + foundFpr : ""
            if (matchesUsedKey) {
                page._notice = qsTr("keys.openpgp.org has the sender's key:\n%1%2\nThe key this message used (0x%3) belongs to it (encryption subkey). Verify the fingerprint, then import.")
                               .arg(who).arg(fp).arg(page._missingKeyId)
            } else {
                page._notice = qsTr("⚠ SECURITY: the message used key 0x%1, but a DIFFERENT key is published for this address:\n%2%3\nThis can mean an old/wrong/forged key. Only import if you trust this.")
                               .arg(page._missingKeyId).arg(who).arg(fp)
            }
        }
    }

    // Resolve the missing key: exact key-id first, then the sender's verified
    // address. The plugin NEVER auto-imports — it reports the found key via
    // keyCandidate() and the user decides.
    function _searchKeyserver() {
        page._candidatePending = false
        Gpg.resolveMissingKey(page._missingKeyId, page.senderEmail)
    }

    function _statusColor(r) {
        if (r.revoked || !r.inKeyring) return "#ff4d4d"
        if (r.expired) return "#ffa726"
        return "#4caf50"
    }

    function _asText() {
        var t = "Format: " + (info.format || "?") + "\n"
        if (_blindCount > 0) t += "Blind copy recipients: " + _blindCount + "\n" + _blindWho + "\n"
        for (var i = 0; i < _recips.length; ++i) {
            var r = _recips[i]
            t += "\nKey 0x" + r.keyId + "  [" + r.status + "]  " + _roles[i] + "\n"
            var uids = r.uids || []
            for (var j = 0; j < uids.length; ++j) t += "  " + uids[j] + "\n"
            if (r.created) t += "  created " + r.created + "\n"
            if (r.algo)    t += "  " + r.algo + " " + (r.bits || "") + " bit\n"
            if (r.fpr)     t += "  fpr " + r.fpr + "\n"
            if (r.hasSecret) t += "  secret key present → decryptable\n"
        }
        return t
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                // Only when a key shown here is missing from the keyring.
                text: qsTr("Import key from message")
                visible: page.importKey !== null && page._anyMissing
                onClicked: {
                    var r = page.importKey()
                    if (r && r.length > 0) page._notice = r   // "" → wait for importFinished
                }
            }
            MenuItem {
                text: qsTr("Search key on keys.openpgp.org")
                visible: page._anyMissing
                onClicked: page._searchKeyserver()
            }
            MenuItem {
                text: qsTr("Copy to clipboard")
                onClicked: Clipboard.text = page._asText()
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader { title: page.title }

            Label {
                visible: page._notice !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                text: page._notice
                color: (page._candidatePending && !page._candidateOk) ? "#ff4d4d" : Theme.highlightColor
                font.pixelSize: Theme.fontSizeSmall
            }
            // Import the found key — only on the user's explicit decision.
            Button {
                visible: page._candidatePending
                anchors.horizontalCenter: parent.horizontalCenter
                text: page._candidateOk ? qsTr("Import this key") : qsTr("Import anyway")
                onClicked: { page._candidatePending = false; Gpg.importPendingKey() }
            }

            // Format
            DetailItem {
                label: qsTr("Format")
                value: info.format ? info.format : "—"
            }

            // Blind copies. Worth its own box: this is the one thing the message
            // headers deliberately do NOT show, and the ciphertext does.
            Rectangle {
                visible: page._blindCount > 0
                x: Theme.horizontalPageMargin
                width: page.width - 2 * Theme.horizontalPageMargin
                height: blind.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: Theme.rgba("#ffa726", 0.15)

                Label {
                    id: blind
                    x: Theme.paddingMedium
                    y: Theme.paddingMedium
                    width: parent.width - 2 * Theme.paddingMedium
                    wrapMode: Text.WordWrap
                    font.pixelSize: Theme.fontSizeSmall
                    color: "#ffa726"
                    text: qsTr("Blind copy — named in no header of this message:")
                          + "\n" + page._blindWho
                          + "\n\n" + qsTr("A blind copy is hidden from the headers only. Every recipient key is named in the encrypted data itself, so anyone who receives this message can read this list too.")
                }
            }

            Label {
                visible: page._unknownCount > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Further recipient keys above cannot be named — they are not in your keyring. Look them up on keys.openpgp.org from the menu.")
            }

            Label {
                visible: info.error && info.error.length > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                text: info.error ? info.error : ""
                color: "#ff4d4d"
                font.pixelSize: Theme.fontSizeSmall
            }

            SectionHeader {
                visible: page._recips.length > 0
                text: qsTr("Encrypted to %1 key(s)").arg(page._recips.length)
            }

            Label {
                visible: page._addressedElsewhere !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Addressed to, but not a recipient of this copy: %1").arg(page._addressedElsewhere)
            }

            Repeater {
                model: page._recips
                delegate: Column {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    spacing: 2

                    // Where this recipient stands in the headers — or that it
                    // stands nowhere in them (blind copy).
                    Label {
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: page._roles[index] === "blind"
                        text: page._roleText(index)
                        color: page._roleColor(index)
                    }

                    // Status (rot bei revoked/fehlend, orange bei abgelaufen)
                    Label {
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeMedium
                        text: qsTr("Status: ") + modelData.status
                        color: page._statusColor(modelData)
                    }
                    Label {
                        width: parent.width
                        truncationMode: TruncationMode.Fade
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: "monospace"
                        text: "0x" + modelData.keyId
                        color: Theme.highlightColor
                    }
                    Repeater {
                        model: modelData.uids
                        delegate: Label {
                            width: page.width - 2 * Theme.horizontalPageMargin
                            wrapMode: Text.WordWrap
                            font.pixelSize: Theme.fontSizeSmall
                            text: modelData
                            color: Theme.primaryColor
                        }
                    }
                    Label {
                        visible: !modelData.inKeyring
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: qsTr("This key is not in your keyring.")
                        color: Theme.secondaryColor
                    }
                    // While the key is missing/unverified, flag the sender's
                    // address as unverified (cleared once a key is imported).
                    Label {
                        visible: !modelData.inKeyring && page.senderEmail !== "" && !page._verified
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: page.senderEmail + " — not verified"
                        color: "#ff4d4d"
                    }
                    Label {
                        visible: modelData.created && modelData.created.length > 0
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        text: qsTr("Created: ") + modelData.created
                              + (modelData.algo ? "   " + modelData.algo + " " + modelData.bits + " bit" : "")
                    }
                    Label {
                        visible: modelData.fpr && modelData.fpr.length > 0
                        width: parent.width
                        wrapMode: Text.WrapAnywhere
                        font.pixelSize: Theme.fontSizeExtraSmall
                        font.family: "monospace"
                        color: Theme.secondaryColor
                        text: qsTr("Fingerprint: ") + modelData.fpr
                    }
                    Label {
                        visible: modelData.hasSecret
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: "#4caf50"
                        text: qsTr("✓ secret key present — decryptable")
                    }
                }
            }

            // Zusammenfassung
            Rectangle {
                x: Theme.horizontalPageMargin
                width: page.width - 2 * Theme.horizontalPageMargin
                height: summary.height + 2 * Theme.paddingMedium
                radius: Theme.paddingSmall
                color: Theme.rgba(page.info.canDecrypt ? "#4caf50" : "#ff4d4d", 0.15)

                Label {
                    id: summary
                    y: Theme.paddingMedium
                    x: Theme.paddingMedium
                    width: parent.width - 2 * Theme.paddingMedium
                    wrapMode: Text.WordWrap
                    font.pixelSize: Theme.fontSizeSmall
                    color: page.info.canDecrypt ? "#4caf50" : "#ff4d4d"
                    text: !page.info.found
                          ? qsTr("No recipient key IDs found — this may not be an encrypted message.")
                          : page.info.canDecrypt
                            ? qsTr("You hold a secret key for a recipient above — you CAN decrypt this message.")
                            : qsTr("You do NOT hold a secret key for any recipient — you cannot decrypt this. The sender probably used an old or wrong key of yours.")
                }
            }

            Label {
                visible: page.info.signedSeen === true
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("The encrypted data also carries a signature; the signer is shown after decryption.")
            }
        }
        VerticalScrollDecorator { }
    }
}
