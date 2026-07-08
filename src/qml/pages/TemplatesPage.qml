import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// Templates of one account. Deliberately NOT driven by FolderListModel: a local
// custom folder is not reliably surfaced there on every account type (POP3), so
// this page queries the Templates folder's messages directly via the plugin.
// Tapping a template opens the composer prefilled (the template stays); the
// context menu deletes a single template. Server folders are never touched —
// templates live in a local, non-synchronized folder.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property int accountId: 0
    property string accountName: ""

    function _reload() {
        templateModel.clear()
        if (page.accountId <= 0) return
        var list = Gpg.listTemplates(page.accountId)
        for (var i = 0; i < list.length; ++i)
            templateModel.append(list[i])
    }

    // Delete from the PAGE scope (not the delegate's): a delegate's remorse
    // callback can fire after its ListItem was torn down, where the imported
    // Gpg singleton resolves to undefined (TypeError) and touching freed delegate
    // state can crash. Remove only the affected row instead of clear()+rebuild so
    // sibling delegates with a pending remorse are not destroyed underneath it.
    function _deleteTemplate(mid) {
        if (!Gpg.deleteTemplate(mid))
            return
        for (var i = 0; i < templateModel.count; ++i) {
            if (templateModel.get(i).id === mid) {
                templateModel.remove(i)
                break
            }
        }
    }

    ListModel { id: templateModel }

    onStatusChanged: if (status === PageStatus.Active) _reload()

    SilicaListView {
        id: listView
        anchors.fill: parent
        model: templateModel

        header: PageHeader {
            title: qsTr("Templates")
            description: page.accountName
        }

        delegate: ListItem {
            id: item
            contentHeight: Theme.itemSizeMedium

            // Compose a NEW message from this template; the template is untouched
            // and remains for reuse.
            onClicked: pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                      { fromTemplateId: model.id,
                                        composeAccountId: page.accountId })

            function removeTemplate() {
                var mid = model.id
                item.remorseAction(qsTr("Deleting"), function() {
                    page._deleteTemplate(mid)
                })
            }

            menu: ContextMenu {
                MenuItem {
                    text: qsTr("Delete")
                    onClicked: item.removeTemplate()
                }
            }

            Column {
                anchors.verticalCenter: parent.verticalCenter
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin

                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    text: model.subject !== "" ? model.subject : qsTr("(no subject)")
                    color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                }
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: model.encrypt && model.sign
                          ? qsTr("Encrypted + signed (%1)").arg(model.cryptoKind)
                          : model.encrypt ? qsTr("Encrypted (%1)").arg(model.cryptoKind)
                          : model.sign ? qsTr("Signed (%1)").arg(model.cryptoKind)
                          : qsTr("Not encrypted")
                }
            }
        }

        ViewPlaceholder {
            enabled: templateModel.count === 0
            text: qsTr("No templates")
            hintText: qsTr("Save a message as a template from the composer")
        }

        VerticalScrollDecorator { }
    }
}
