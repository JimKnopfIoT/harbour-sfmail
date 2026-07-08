import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// Ausführliche Anzeige eines Schlüssels: alle Metadaten (Status, Erstellung/
// Ablauf, Algorithmus/Länge, Fähigkeiten, UIDs, Subkeys) und darunter der
// vollständige ASCII-Armor-Block.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property string fingerprint: ""
    property var d: ({})
    property string _notice: ""
    property color _noticeColor: Theme.highlightColor

    function _setNotice(msg, ok) {
        page._notice = msg
        page._noticeColor = ok ? "#8bc34a" : "#ff6b6b"
    }

    // Standard reminder appended to every secret-material backup we drop into the
    // (unsandboxed) Documents folder.
    readonly property string _offDeviceHint:
        qsTr("It is encrypted with your passphrase, but lies outside the app sandbox. Copy it to safe off-device storage and then delete it from the phone.")

    // Back up the SECRET key to Documents (asks the passphrase first).
    function _backupSecret() {
        var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                 { info: qsTr("Passphrase of this key (to back it up)") })
        dlg.accepted.connect(function() {
            var p = Gpg.saveKeyToDocuments(page.fingerprint, true, dlg.passphrase)
            if (p.length > 0) page._setNotice(qsTr("Secret key backed up to %1.").arg(p) + " " + page._offDeviceHint, true)
            else page._setNotice(qsTr("Backup failed — wrong passphrase?"), false)
        })
    }

    // Extend the key's (and subkeys') expiry by 2 years (asks the passphrase).
    function _extend() {
        var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                 { info: qsTr("Passphrase of this key (to extend it)") })
        dlg.accepted.connect(function() { Gpg.extendKey(page.fingerprint, "2y", dlg.passphrase) })
    }

    // SAFE: save the revocation certificate (with its protective colon) to Documents.
    function _saveRevCert() {
        var p = Gpg.saveRevocationCert(page.fingerprint)
        if (p.length > 0)
            page._setNotice(qsTr("Revocation certificate saved to %1. Keep it safe; it lets you revoke this key later even without the passphrase.").arg(p) + " " + page._offDeviceHint, true)
        else
            page._setNotice(qsTr("No revocation certificate available for this key."), false)
    }

    // DESTRUCTIVE: revoke now — extra confirmation first.
    function _revoke() {
        var dlg = pageStack.push(Qt.resolvedUrl("ConfirmDialog.qml"), {
            question: qsTr("Really revoke this key?"),
            warning: qsTr("This is IRREVERSIBLE. The key can never be used to encrypt to you again. Afterwards publish it so others learn it is revoked."),
            acceptText: qsTr("Revoke")
        })
        dlg.accepted.connect(function() { Gpg.revokeKey(page.fingerprint) })
    }

    Connections {
        target: Gpg
        onKeyOpFinished: {
            page._setNotice(message, ok)
            page.d = Gpg.keyDetails(page.fingerprint)   // refresh status (expiry/revoked)
        }
    }

    readonly property var _armorLines: (d && d.armored && d.armored.length > 0)
                                       ? d.armored.split("\n") : []

    Component.onCompleted: page.d = Gpg.keyDetails(page.fingerprint)

    function _statusColor() {
        if (!d) return Theme.secondaryColor
        if (d.revoked) return "#ff4d4d"
        if (d.expired) return "#ffa726"
        return "#4caf50"
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                text: qsTr("Publish to keys.openpgp.org")
                onClicked: Gpg.publishKey(page.fingerprint)
            }
            MenuItem {
                visible: d && d.hasSecret === true && d.revoked !== true
                text: qsTr("Revoke this key…")
                onClicked: page._revoke()
            }
            MenuItem {
                visible: d && d.hasSecret === true && Gpg.hasRevocationCert(page.fingerprint)
                text: qsTr("Save revocation certificate…")
                onClicked: page._saveRevCert()
            }
            MenuItem {
                visible: d && d.hasSecret === true && d.revoked !== true
                text: qsTr("Extend validity (2 years)…")
                onClicked: page._extend()
            }
            MenuItem {
                visible: d && d.hasSecret === true
                text: qsTr("Back up secret key to Documents…")
                onClicked: page._backupSecret()
            }
            MenuItem {
                text: qsTr("Save public key to Documents")
                onClicked: {
                    var p = Gpg.saveKeyToDocuments(page.fingerprint, false, "")
                    if (p.length > 0) page._setNotice(qsTr("Public key saved to %1").arg(p), true)
                    else page._setNotice(qsTr("Save failed"), false)
                }
            }
            MenuItem {
                text: qsTr("Copy public key block")
                onClicked: Clipboard.text = (d.armored || "")
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingSmall

            PageHeader { title: qsTr("Key details") }

            Label {
                visible: page._notice.length > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: page._noticeColor
                text: page._notice
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                font.pixelSize: Theme.fontSizeMedium
                text: qsTr("Status: ") + (d.status ? d.status : "—")
                      + (d.hasSecret ? "  ·  " + qsTr("secret key present") : "")
                color: page._statusColor()
            }

            // Identities
            SectionHeader { text: qsTr("Identities (%1)").arg((d.uids ? d.uids.length : 0)) }
            Repeater {
                model: d.uids ? d.uids : []
                delegate: Label {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.WordWrap
                    font.pixelSize: Theme.fontSizeSmall
                    text: modelData
                    color: Theme.primaryColor
                }
            }

            // Primary key
            SectionHeader { text: qsTr("Primary key") }
            DetailItem { label: qsTr("Key ID"); value: d.keyId ? "0x" + d.keyId : "—" }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Fingerprint: ") + (d.fingerprint ? d.fingerprint : "—")
            }
            DetailItem { label: qsTr("Algorithm"); value: (d.algo || "—") + (d.bits ? "  " + d.bits + " bit" : "") }
            DetailItem { label: qsTr("Created"); value: d.created ? d.created : "—" }
            DetailItem {
                label: qsTr("Expires")
                value: d.expires ? d.expires : "—"
            }
            DetailItem { label: qsTr("Usage"); value: d.caps ? d.caps : "—" }

            // Subkeys
            SectionHeader {
                visible: d.subkeys && d.subkeys.length > 0
                text: qsTr("Subkeys (%1)").arg(d.subkeys ? d.subkeys.length : 0)
            }
            Repeater {
                model: d.subkeys ? d.subkeys : []
                delegate: Column {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    spacing: 0
                    Label {
                        width: parent.width
                        truncationMode: TruncationMode.Fade
                        font.family: "monospace"
                        font.pixelSize: Theme.fontSizeExtraSmall
                        text: "0x" + modelData.keyId + "  [" + (modelData.caps || "") + "]"
                        color: (modelData.revoked || modelData.expired) ? "#ff4d4d" : Theme.highlightColor
                    }
                    Label {
                        width: parent.width
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        text: (modelData.algo || "") + " " + (modelData.bits || "") + " bit"
                              + "  ·  " + qsTr("created ") + (modelData.created || "?")
                              + "  ·  " + qsTr("expires ") + (modelData.expires || "?")
                    }
                }
            }

            // Full armored block
            SectionHeader { text: qsTr("Public key block") }
            Repeater {
                model: page._armorLines
                delegate: Label {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    text: modelData
                    textFormat: Text.PlainText
                    wrapMode: Text.WrapAnywhere
                    font.family: "monospace"
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                }
            }
        }
        VerticalScrollDecorator { }
    }
}
