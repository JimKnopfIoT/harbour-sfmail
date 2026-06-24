import QtQuick 2.6
import Sailfish.Silica 1.0
import org.nemomobile.contacts 1.0

// Address-book picker: lists contacts that have an e-mail address, with live
// search. Tapping a contact with one address picks it; with several, a menu lets
// you choose. Result via picked(email). Read-only — never modifies contacts.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations
    signal picked(string email)

    SilicaListView {
        id: list
        anchors.fill: parent

        header: Column {
            width: parent.width
            PageHeader { title: qsTr("Address book") }
            SearchField {
                id: search
                width: parent.width
                placeholderText: qsTr("Search contacts")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                Component.onCompleted: forceActiveFocus()
            }
        }

        model: PeopleModel {
            filterType: PeopleModel.FilterAll
            requiredProperty: PeopleModel.EmailAddressRequired
            filterPattern: search.text
        }

        delegate: ListItem {
            id: item
            property var emails: model.person ? model.person.emailDetails : []
            contentHeight: cc.height + Theme.paddingMedium
            onClicked: {
                if (item.emails.length === 1) { page.picked("" + item.emails[0].address); pageStack.pop() }
                else if (item.emails.length > 1) emailMenu.open(item)
            }
            Column {
                id: cc
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                Label {
                    width: parent.width; truncationMode: TruncationMode.Fade
                    text: ("" + model.displayLabel) !== "" ? model.displayLabel : qsTr("(no name)")
                }
                Label {
                    width: parent.width; truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall; color: Theme.secondaryColor
                    text: item.emails.length === 1 ? ("" + item.emails[0].address)
                          : item.emails.length > 1 ? qsTr("%1 addresses — tap to choose").arg(item.emails.length)
                          : ""
                }
            }
            ContextMenu {
                id: emailMenu
                Repeater {
                    model: item.emails
                    MenuItem {
                        text: "" + modelData.address
                        onClicked: { page.picked("" + modelData.address); pageStack.pop() }
                    }
                }
            }
        }

        ViewPlaceholder {
            enabled: list.count === 0
            text: search.text !== "" ? qsTr("No matches") : qsTr("No contacts with an e-mail address")
        }
        VerticalScrollDecorator {}
    }
}
