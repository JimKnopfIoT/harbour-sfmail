import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

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
        for (var i = 0; i < _recips.length; ++i) {
            var r = _recips[i]
            t += "\nKey 0x" + r.keyId + "  [" + r.status + "]\n"
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

            Repeater {
                model: page._recips
                delegate: Column {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    spacing: 2

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
