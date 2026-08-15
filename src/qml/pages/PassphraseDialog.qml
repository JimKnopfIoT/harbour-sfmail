import QtQuick 2.6
import Sailfish.Silica 1.0

// Fragt die Passphrase des geheimen Schlüssels ab (für Signieren/Entschlüsseln).
// Ergebnis über das accepted-Signal via Property passphrase.
Dialog {
    id: dialog
    allowedOrientations: defaultAllowedOrientations

    property alias passphrase: field.text
    property string info: ""

    // Optional: offer to delete the import SOURCE file after a successful import.
    // The caller sets offerDeleteSource=true and reads deleteSource afterwards.
    property bool offerDeleteSource: false
    property bool deleteSource: deleteSwitch.checked

    canAccept: field.text.length > 0

    // Hygiene: whatever pushes THIS dialog aside — accept/cancel (the pop), a
    // page on top, the task switcher — must not leave the passphrase armed in
    // the field. Safe for the callers: `accepted` fires synchronously inside
    // pageStack.navigateForward(), BEFORE the pop changes our status, so their
    // handlers have already read `passphrase` when this clears it.
    onStatusChanged: {
        if (status !== PageStatus.Active) {
            field.text = ""
        }
    }
    Connections {
        target: Qt.application
        onActiveChanged: {
            if (!Qt.application.active) {
                field.text = ""
            }
        }
    }

    Column {
        width: parent.width
        spacing: Theme.paddingMedium

        DialogHeader { acceptText: qsTr("OK"); title: qsTr("Passphrase") }

        Label {
            visible: dialog.info.length > 0
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.WordWrap
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.secondaryColor
            text: dialog.info
        }

        PasswordField {
            id: field
            width: parent.width
            label: qsTr("Secret key passphrase")
            // PasswordField's own default lacks ImhSensitiveData — that flag is
            // what keeps the input out of the keyboard's learning database.
            inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
            focus: true
            EnterKey.iconSource: "image://theme/icon-m-enter-accept"
            EnterKey.onClicked: if (dialog.canAccept) dialog.accept()
        }

        // Import-source cleanup: explains WHY, then offers to delete the file.
        Label {
            visible: dialog.offerDeleteSource
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.WordWrap
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.secondaryColor
            text: qsTr("After import, the key lives safely in the app's encrypted keyring. The file you imported stays where you picked it (e.g. Downloads), outside the app sandbox, where other apps could read it — so it is no longer needed on the device. If you have a backup elsewhere, delete it here.")
        }
        TextSwitch {
            id: deleteSwitch
            visible: dialog.offerDeleteSource
            checked: false
            text: qsTr("Delete the import file after import")
            description: qsTr("Only if you have another backup. This cannot be undone.")
        }
    }
}
