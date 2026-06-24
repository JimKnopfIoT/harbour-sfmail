import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// Confirm a 1-click PGP key import. The key was already inspected by the plugin
// (Gpg.inspectKeyForImport) and stashed; we only show what it is and warn about
// revoked/expired keys or a conflicting key already stored for the same address.
// Accepting imports the stashed key via Gpg.importPendingKey() — we NEVER import
// without this explicit confirmation (mirrors the S/MIME sender-cert flow).
Dialog {
    id: dialog
    allowedOrientations: defaultAllowedOrientations

    // The QVariantMap from keyImportCandidate(info).
    property var info: ({})

    readonly property bool _revoked: info.revoked === true
    readonly property bool _expired: info.expired === true
    readonly property var  _conflicts: info.conflicts ? info.conflicts : []
    readonly property bool _inKeyring: info.inKeyring === true
    readonly property bool _hasConflict: _conflicts.length > 0
    readonly property bool _senderKnown: info.senderKnown === true
    readonly property bool _senderMatches: info.senderMatches === true
    readonly property bool _senderMismatch: _senderKnown && !_senderMatches

    function _grouped(fpr) {
        var s = ("" + fpr).toUpperCase().replace(/\s/g, "")
        var out = ""
        for (var i = 0; i < s.length; i += 4)
            out += (i > 0 ? " " : "") + s.substr(i, 4)
        return out
    }

    onAccepted: Gpg.importPendingKey()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height

        Column {
            id: col
            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader {
                acceptText: dialog._inKeyring && !dialog._hasConflict && !dialog._senderMismatch ? qsTr("Re-import")
                          : (dialog._revoked || dialog._expired || dialog._hasConflict || dialog._senderMismatch) ? qsTr("Import anyway")
                          : qsTr("Import")
                cancelText: qsTr("Cancel")
                title: qsTr("Import public key?")
            }

            // --- what the key is ---------------------------------------------
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                text: info.uids ? info.uids : qsTr("(no user id)")
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.highlightColor
            }

            Item { width: 1; height: Theme.paddingSmall }

            DetailItem { label: qsTr("Key ID"); value: "0x" + (info.keyId ? info.keyId : "?") }
            DetailItem {
                label: qsTr("Fingerprint")
                value: dialog._grouped(info.fpr)
            }
            DetailItem {
                label: qsTr("Algorithm")
                value: (info.algo ? info.algo : "?") + (info.bits ? " " + info.bits + " bit" : "")
            }
            DetailItem { label: qsTr("Created"); value: info.created ? info.created : "?" }
            DetailItem {
                label: qsTr("Expires")
                value: info.expires ? info.expires : qsTr("never")
            }

            Item { width: 1; height: Theme.paddingSmall }

            // --- does this key belong to the SENDER? (most important check) ---
            Label {
                visible: dialog._senderMismatch
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#ff5050"
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("⚠ This key is NOT issued for the sender's address (%1). Its addresses are: %2. Only import it if you are sure it really is this sender's key.")
                      .arg(info.senderEmail ? info.senderEmail : "?")
                      .arg(info.uids ? info.uids : "?")
            }
            Label {
                visible: dialog._senderKnown && dialog._senderMatches
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#60c060"
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("✓ This key belongs to the sender's address (%1).").arg(info.senderEmail)
            }

            // --- warnings / status -------------------------------------------
            Label {
                visible: dialog._revoked
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#ff5050"
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("⚠ This key has been REVOKED by its owner. It should not be used to encrypt — import only to read old messages or to verify old signatures.")
            }
            Label {
                visible: dialog._expired && !dialog._revoked
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#ffa030"
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("This key is EXPIRED. You cannot encrypt to it until the owner extends it.")
            }

            // One block per conflicting key already in the keyring.
            Repeater {
                model: dialog._conflicts
                delegate: Label {
                    x: Theme.horizontalPageMargin
                    width: dialog.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.WordWrap
                    color: "#ff5050"
                    font.pixelSize: Theme.fontSizeSmall
                    text: qsTr("You already have a DIFFERENT key for %1:\n0x%2  (%3)\nImporting adds a SECOND key for this address — make sure this new key is genuine before you trust it.")
                          .arg(modelData.email)
                          .arg(modelData.keyId)
                          .arg(dialog._grouped(modelData.fpr))
                }
            }

            Label {
                visible: dialog._inKeyring
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("This exact key is already in your keyring. Re-importing just refreshes it (e.g. new signatures or a longer expiry).")
            }

            Label {
                visible: !dialog._revoked && !dialog._expired && !dialog._hasConflict && !dialog._inKeyring
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#60c060"
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("This key is new and valid. Verify the fingerprint with the owner through a separate channel before you rely on it.")
            }
        }

        VerticalScrollDecorator {}
    }
}
