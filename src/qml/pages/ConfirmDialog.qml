import QtQuick 2.6
import Sailfish.Silica 1.0

// Kleiner Ja/Nein-Bestätigungsdialog. accepted() wird nur bei Bestätigung
// ausgelöst. Bewusst als eigener Schritt, damit ein versehentliches Antippen
// nicht sofort löscht.
Dialog {
    id: dialog
    allowedOrientations: defaultAllowedOrientations

    property string question: qsTr("Are you sure?")
    property string warning: ""
    property string acceptText: qsTr("Delete")

    Column {
        width: parent.width
        spacing: Theme.paddingLarge

        DialogHeader {
            acceptText: dialog.acceptText
            cancelText: qsTr("Cancel")
            title: dialog.question
        }

        Label {
            visible: dialog.warning !== ""
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.WordWrap
            text: dialog.warning
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeSmall
        }
    }
}
