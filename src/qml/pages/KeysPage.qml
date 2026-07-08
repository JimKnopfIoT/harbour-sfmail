import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import SFMail.Gpg 1.0

// Key-Verwaltung für den System-Keyring ~/.gnupg (den auch der native QMF-
// Krypto-Pfad nutzt). Liste, Import (Datei oder Text), Export, Löschen.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property string _noticeText: ""
    property color _noticeColor: Theme.highlightColor
    property bool _busy: false   // a key generation is running

    function refresh() {
        keyModel.clear()
        var keys = Gpg.publicKeys()
        for (var i = 0; i < keys.length; ++i)
            keyModel.append(keys[i])
    }

    Component.onCompleted: refresh()

    Connections {
        target: Gpg
        onKeysChanged: page.refresh()
        onImportFinished: page._notice(ok ? qsTr("Imported %1 key(s)").arg(imported)
                                          : qsTr("Import failed: %1").arg(error), ok)
        onKeyDeleted: page._notice(ok ? qsTr("Key deleted") : qsTr("Delete failed: %1").arg(error), ok)
        onKeyGenStarted: {
            page._busy = true
            page._notice(qsTr("Generating a 4096-bit key — this can take a minute…"), true)
        }
        onKeyGenFinished: {
            page._busy = false
            if (ok)
                page._notice(fingerprint.length > 0
                             ? qsTr("New key created: %1").arg("…" + fingerprint.slice(-16))
                             : qsTr("New key created."), true)
            else
                page._notice(qsTr("Key generation failed: %1").arg(error), false)
        }
    }

    function _notice(msg, ok) {
        page._noticeText = msg
        page._noticeColor = ok ? Theme.highlightColor : "#ff6b6b"
    }

    ListModel { id: keyModel }

    Component {
        id: keyPicker
        FilePickerPage {
            allowedOrientations: defaultAllowedOrientations
            title: qsTr("Import PGP key")
            nameFilters: [ "*.asc", "*.gpg", "*.pgp", "*.key", "*" ]
            onSelectedContentPropertiesChanged: Gpg.importKeyFile(selectedContentProperties.filePath)
        }
    }

    Component {
        id: pasteDialog
        Dialog {
            allowedOrientations: defaultAllowedOrientations
            property alias text: ta.text
            SilicaFlickable {
                anchors.fill: parent
                contentHeight: c.height
                Column {
                    id: c; width: parent.width
                    DialogHeader { acceptText: qsTr("Import") }
                    TextArea {
                        id: ta; width: parent.width
                        label: qsTr("Paste public key block")
                        placeholderText: "-----BEGIN PGP PUBLIC KEY BLOCK-----"
                    }
                }
            }
            onAccepted: if (ta.text.length > 0) Gpg.importKeyText(ta.text)
        }
    }

    SilicaListView {
        id: list
        anchors.fill: parent
        model: keyModel

        PullDownMenu {
            MenuItem {
                text: qsTr("Generate new key…")
                enabled: !page._busy
                onClicked: {
                    var dlg = pageStack.push(Qt.resolvedUrl("GenerateIdentityDialog.qml"), {
                        heading: qsTr("Generate PGP key"),
                        intro: qsTr("Creates a new RSA-4096 OpenPGP key (signing + encryption) in your keyring. Highest security; the passphrase is mandatory."),
                        commandText:
                            "gpg --batch --pinentry-mode loopback --passphrase-fd 0 \\\n" +
                            "    --quick-generate-key \"Max Mustermann <max@example.org>\" \\\n" +
                            "    rsa4096 cert,sign 2y\n" +
                            "gpg --batch --quick-add-key <FINGERPRINT> rsa4096 encrypt 2y"
                    })
                    dlg.accepted.connect(function() {
                        Gpg.generateKey(dlg.genName, dlg.genEmail, dlg.genPass)
                    })
                }
            }
            MenuItem {
                text: qsTr("Import from file…")
                onClicked: pageStack.push(keyPicker)
            }
            MenuItem {
                text: qsTr("Paste key…")
                onClicked: pageStack.push(pasteDialog)
            }
        }

        header: Column {
            width: list.width
            PageHeader { title: qsTr("PGP Keys") }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Keyring: %1").arg(Gpg.gnupgHome)
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                visible: text.length > 0
                font.pixelSize: Theme.fontSizeExtraSmall
                text: page._noticeText
                color: page._noticeColor
            }
        }

        delegate: ListItem {
            id: item
            contentHeight: Math.max(Theme.itemSizeMedium, infoCol.height + Theme.paddingMedium)

            menu: ContextMenu {
                MenuItem {
                    text: qsTr("Show / export public key")
                    onClicked: pageStack.push(Qt.resolvedUrl("KeyDetailPage.qml"),
                                              { fingerprint: model.fingerprint })
                }
                MenuItem {
                    text: model.hasSecret ? qsTr("Delete key (incl. secret)") : qsTr("Delete key")
                    onClicked: {
                        var fpr = model.fingerprint, sec = model.hasSecret
                        var dlg = pageStack.push(Qt.resolvedUrl("ConfirmDialog.qml"), {
                            question: qsTr("Really delete this key?"),
                            warning: sec ? qsTr("This includes your PRIVATE key. Without a backup it cannot be recovered.")
                                         : qsTr("The public key will be removed from your keyring."),
                            acceptText: qsTr("Delete")
                        })
                        dlg.accepted.connect(function() {
                            item.remorseAction(qsTr("Deleting"),
                                               function() { Gpg.deleteKey(fpr, sec) })
                        })
                    }
                }
            }

            Column {
                id: infoCol
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    text: (model.name && model.name.length ? model.name : model.uid)
                          + (model.email && model.email.length ? "  <" + model.email + ">" : "")
                    color: model.expired || model.revoked ? "#ff6b6b"
                           : (item.highlighted ? Theme.highlightColor : Theme.primaryColor)
                }
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: "0x" + model.keyId
                          + (model.algo ? "  • " + model.algo + " " + (model.bits || "") : "")
                          + (model.hasSecret ? "  • " + qsTr("private") : "")
                          + (model.revoked ? "  • " + qsTr("revoked") : model.expired ? "  • " + qsTr("expired") : "")
                }
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: qsTr("created ") + (model.created || "?")
                          + "  • " + qsTr("expires ") + (model.expires || "?")
                }
            }
        }

        ViewPlaceholder {
            enabled: keyModel.count === 0
            text: qsTr("No keys")
            hintText: qsTr("Import a key with the pull-down menu")
        }

        VerticalScrollDecorator { }
    }
}
