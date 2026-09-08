import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// The remembered addresses: the user's own small address list, filled by hand
// from the messages they read. Everything about it is editable here — name,
// address, and removal — because a collection nobody can correct turns into a
// collection nobody trusts.
//
// The file behind it is plain JSON with mode 0600. That is a decision: these
// same addresses already sit in clear text in every stored message and in the
// platform's own address book, so a passphrase here would protect nothing and
// cost a prompt every session.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    ListModel { id: entries }

    // Where else the device knows these addresses from. A remembered entry that
    // duplicates the address book is not an error, but the user asked to see it
    // — a second copy is one they have to keep in step by hand.
    AddressKnowledge { id: known }

    // The address book answers late; when it does, the rows have to be built
    // again, or they would keep claiming the entries are known nowhere else.
    Connections {
        target: known
        onRevisionChanged: page._reload()
    }

    function _elsewhere(address) {
        var f = known.sourceFlags(address)
        f.remembered = false            // this list itself is not news here
        return known.sourceNames(f).join(", ")
    }

    function _reload() {
        entries.clear()
        var rows = Gpg.rememberedAddresses()
        var list = []
        for (var i = 0; i < rows.length; ++i)
            list.push({ "name": "" + (rows[i].name ? rows[i].name : ""),
                        "address": "" + rows[i].address,
                        "elsewhere": page._elsewhere(rows[i].address) })
        list.sort(function(a, b) {
            var ka = (a.name !== "" ? a.name : a.address).toLowerCase()
            var kb = (b.name !== "" ? b.name : b.address).toLowerCase()
            return ka < kb ? -1 : ka > kb ? 1 : 0
        })
        for (var j = 0; j < list.length; ++j) entries.append(list[j])
    }

    function _edit(oldAddress, name, address) {
        // An address change is a removal plus an entry: the address is the key
        // of the record, so editing it in place would leave the old one behind.
        if (("" + oldAddress).toLowerCase() !== ("" + address).toLowerCase())
            Gpg.forgetAddress("" + oldAddress)
        Gpg.rememberAddress("" + address, "" + name)
        page._reload()
    }

    Component.onCompleted: page._reload()

    SilicaListView {
        id: list
        anchors.fill: parent
        model: entries

        PullDownMenu {
            MenuItem {
                text: qsTr("Add address")
                onClicked: {
                    var dlg = pageStack.push(editDialog,
                                             { entryName: "", entryAddress: "",
                                               originalAddress: "" })
                    dlg.accepted.connect(function() {
                        page._edit("", dlg.entryName, dlg.entryAddress)
                    })
                }
            }
        }

        header: PageHeader { title: qsTr("Remembered addresses") }

        delegate: ListItem {
            id: item
            contentHeight: cc.height + Theme.paddingMedium
            ListView.onRemove: animateRemoval(item)

            function remove() {
                remorseAction(qsTr("Forgetting"), function() {
                    Gpg.forgetAddress("" + model.address)
                    page._reload()
                })
            }

            onClicked: {
                var dlg = pageStack.push(editDialog,
                                         { entryName: "" + model.name,
                                           entryAddress: "" + model.address,
                                           originalAddress: "" + model.address })
                var was = "" + model.address
                dlg.accepted.connect(function() {
                    page._edit(was, dlg.entryName, dlg.entryAddress)
                })
            }

            Column {
                id: cc
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                Label {
                    width: parent.width; truncationMode: TruncationMode.Fade
                    text: ("" + model.name) !== "" ? model.name : model.address
                }
                Label {
                    width: parent.width; truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: (("" + model.name) !== "" ? ("" + model.address) : "")
                          + (("" + model.elsewhere) !== ""
                             ? ((("" + model.name) !== "" ? "  ·  " : "") + model.elsewhere)
                             : "")
                    visible: text !== ""
                }
            }

            menu: ContextMenu {
                MenuItem { text: qsTr("Edit"); onClicked: item.clicked(null) }
                MenuItem { text: qsTr("Forget"); onClicked: item.remove() }
            }
        }

        ViewPlaceholder {
            enabled: entries.count === 0
            text: qsTr("No remembered addresses")
            hintText: qsTr("Press and hold an address in a message to add it here")
        }
        VerticalScrollDecorator {}
    }

    Component {
        id: editDialog
        Dialog {
            id: dlg
            allowedOrientations: defaultAllowedOrientations
            property string entryName: ""
            property string entryAddress: ""
            // The address this dialog started with: it being in the remembered
            // list is not worth saying, that is where we opened it from. A
            // DIFFERENT remembered entry with the same address is worth saying,
            // because saving would fold the two into one.
            property string originalAddress: ""
            // An entry without an address would be a row that can never be used.
            canAccept: addressField.text.trim().indexOf("@") > 0

            onAccepted: {
                dlg.entryName = nameField.text.trim()
                dlg.entryAddress = addressField.text.trim()
            }

            Column {
                width: parent.width
                DialogHeader {
                    acceptText: qsTr("Save")
                    cancelText: qsTr("Cancel")
                    title: qsTr("Remembered address")
                }
                TextField {
                    id: nameField
                    width: parent.width
                    label: qsTr("Name")
                    placeholderText: qsTr("Name")
                    text: dlg.entryAddress === "" && dlg.entryName === "" ? "" : dlg.entryName
                    inputMethodHints: Qt.ImhNoPredictiveText
                    EnterKey.iconSource: "image://theme/icon-m-enter-next"
                    EnterKey.onClicked: addressField.focus = true
                }
                TextField {
                    id: addressField
                    width: parent.width
                    label: qsTr("E-mail address")
                    placeholderText: qsTr("name@example.com")
                    text: dlg.entryAddress
                    inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                                      | Qt.ImhEmailCharactersOnly
                    EnterKey.iconSource: "image://theme/icon-m-enter-close"
                    EnterKey.onClicked: focus = false
                }
                // Says where the typed address is already known, as it is typed.
                // known.revision is what makes it follow the address book, which
                // answers a moment after the dialog opens.
                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.WordWrap
                    color: Theme.secondaryColor
                    font.pixelSize: Theme.fontSizeExtraSmall
                    text: {
                        known.revision                       // re-run when it lands
                        var a = addressField.text.trim()
                        if (a.indexOf("@") < 1) return ""
                        var f = known.sourceFlags(a)
                        if (a.toLowerCase() === ("" + dlg.originalAddress).toLowerCase())
                            f.remembered = false
                        return known.describeFlags(f)
                    }
                    visible: text !== ""
                }
            }
        }
    }
}
