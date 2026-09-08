import QtQuick 2.6
import Sailfish.Silica 1.0

// Confirming that an address should join the remembered list — and saying where
// the device already knows it from. A long press is easy to trigger by accident,
// and a second copy of an address the address book already holds is a copy the
// user has to keep in step by hand; both are reasons to show this step rather
// than to add the entry silently.
Dialog {
    id: dialog
    allowedOrientations: defaultAllowedOrientations

    property string address: ""
    property string entryName: ""

    AddressKnowledge { id: known }

    Column {
        width: parent.width
        spacing: Theme.paddingLarge

        DialogHeader {
            acceptText: qsTr("Remember")
            cancelText: qsTr("Cancel")
            title: qsTr("Add to remembered addresses?")
        }

        Column {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            spacing: Theme.paddingSmall

            Label {
                width: parent.width
                wrapMode: Text.WordWrap
                text: dialog.entryName !== "" ? (dialog.entryName + " <" + dialog.address + ">")
                                              : dialog.address
                color: Theme.highlightColor
                font.pixelSize: Theme.fontSizeSmall
            }
            // The lookup finishes after the dialog is on screen, so the line has
            // to follow it: revision is what makes the call run again.
            Label {
                width: parent.width
                wrapMode: Text.WordWrap
                text: (known.revision, known.statusText(dialog.address))
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeExtraSmall
            }
        }
    }
}
