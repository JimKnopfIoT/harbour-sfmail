import QtQuick 2.6
import Sailfish.Silica 1.0
import Nemo.Email 0.1

// Ordnerliste eines Kontos — dieselben Ordner, die auch die Jolla-Mail-App nutzt
// (gemeinsame QMF-Datenbank). STRIKT READ-ONLY: wir listen Ordner nur auf und
// öffnen ihre Nachrichten. KEINE Lösch-/Erstell-/Umbenennen-Aktionen — Server-
// Ordner werden NIE verändert. (Sync lädt nur herunter, löscht nichts.)
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property int accountId: 0
    property string accountName: ""

    // Map the STANDARD folder type to a localized name (language- and provider-
    // independent, like the Jolla app: INBOX→Posteingang, Sent→Gesendet…). Custom
    // folders keep their server name. Server folders are never modified.
    function _folderName(ft, raw) {
        switch (ft) {
        case EmailFolder.InboxFolder:  return qsTr("Inbox")
        case EmailFolder.OutboxFolder: return qsTr("Outbox")
        case EmailFolder.SentFolder:   return qsTr("Sent")
        case EmailFolder.DraftsFolder: return qsTr("Drafts")
        case EmailFolder.TrashFolder:  return qsTr("Trash")
        case EmailFolder.JunkFolder:   return qsTr("Junk")
        default: return ("" + raw) !== "" ? ("" + raw) : qsTr("(unnamed)")
        }
    }

    EmailAgent { id: emailAgent }

    FolderListModel {
        id: folderModel
        accountKey: page.accountId
    }

    SilicaListView {
        id: listView
        anchors.fill: parent
        model: folderModel

        header: PageHeader {
            title: qsTr("Folders")
            description: page.accountName !== "" ? page.accountName
                         : (emailAgent.synchronizing ? qsTr("Syncing…") : "")
        }

        PullDownMenu {
            // Read-only: pulls the folder list + new mail from the server. Never
            // deletes anything server-side.
            MenuItem {
                text: qsTr("Sync folders")
                onClicked: emailAgent.synchronize(page.accountId)
            }
        }

        delegate: ListItem {
            id: folderItem
            contentHeight: Theme.itemSizeSmall
            onClicked: pageStack.push(Qt.resolvedUrl("MessageListPage.qml"),
                                      { folderAccessor: emailAgent.accessorFromFolderId(model.folderId),
                                        title: _folderName(model.folderType, model.folderName),
                                        accountId: page.accountId })

            Label {
                // Indent sub-folders by their render depth (if provided).
                x: Theme.horizontalPageMargin
                   + (model.folderRenderType > 0 ? model.folderRenderType * Theme.paddingLarge : 0)
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - x - Theme.horizontalPageMargin
                truncationMode: TruncationMode.Fade
                text: _folderName(model.folderType, model.folderName)
                      + (model.folderUnreadCount > 0 ? "  ·  " + model.folderUnreadCount : "")
                color: folderItem.highlighted ? Theme.highlightColor : Theme.primaryColor
            }
        }

        ViewPlaceholder {
            enabled: folderModel.count === 0 && !emailAgent.synchronizing
            text: qsTr("No folders")
            hintText: qsTr("Pull down to sync the account")
        }

        VerticalScrollDecorator { }
    }
}
