import QtQuick 2.6
import Sailfish.Silica 1.0
import Nemo.Email 0.1

// Pick the target folder for a move. Read-only towards the server, exactly like
// FoldersPage: this lists folders and reports the chosen one, it never creates,
// renames or deletes one.
//
// This page exists because the app could delete a message but not put it back.
// A message deleted by accident lands in Trash and stayed there — the only way
// out was Jolla's mail app on the same QMF store. Moving is therefore offered in
// every folder, not as a Trash special case.
Page {
    id: page

    allowedOrientations: defaultAllowedOrientations

    property int accountId: 0
    // The folder the messages sit in — offering it as a destination is pointless.
    property int excludeFolderId: 0
    // Only for the header, so a batch move says how much it is about to move.
    property int messageCount: 1

    // Emitted with the chosen folder before this page pops.
    signal folderPicked(int folderId, string folderName)

    // Same mapping as FoldersPage: the standard folders get a localized name,
    // custom ones keep the name the server gave them.
    function _folderName(ft, raw) {
        switch (ft) {
        case EmailFolder.InboxFolder:  return qsTr("Inbox")
        case EmailFolder.OutboxFolder: return qsTr("Outbox")
        case EmailFolder.SentFolder:   return qsTr("Sent")
        case EmailFolder.DraftsFolder: return qsTr("Drafts")
        case EmailFolder.TrashFolder:  return qsTr("Trash")
        case EmailFolder.JunkFolder:   return qsTr("Junk")
        default: return ("" + raw) === "Templates" ? qsTr("Templates")
                      : ("" + raw) !== "" ? ("" + raw) : qsTr("(unnamed)")
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
            title: qsTr("Move to")
            description: page.messageCount > 1
                         ? qsTr("%1 messages").arg(page.messageCount) : ""
        }

        delegate: ListItem {
            id: folderItem

            // The folder the messages already are in is no destination, and the
            // stale per-account "Templates" folder left over from 0.3.93/0.3.94
            // is hidden here for the same reason FoldersPage hides it.
            readonly property bool _skip: model.folderId === page.excludeFolderId
                                          || ("" + model.folderName) === "Templates"

            visible: !_skip
            contentHeight: _skip ? 0 : Theme.itemSizeSmall

            onClicked: {
                page.folderPicked(model.folderId,
                                  _folderName(model.folderType, model.folderName))
                pageStack.pop()
            }

            Label {
                x: Theme.horizontalPageMargin
                   + (model.folderRenderType > 0
                      ? model.folderRenderType * Theme.paddingLarge : 0)
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - x - Theme.horizontalPageMargin
                truncationMode: TruncationMode.Fade
                text: _folderName(model.folderType, model.folderName)
                color: folderItem.highlighted ? Theme.highlightColor : Theme.primaryColor
            }
        }

        ViewPlaceholder {
            enabled: folderModel.count === 0 && !emailAgent.synchronizing
            text: qsTr("No folders")
            hintText: qsTr("Sync the account first, then the folders show up here.")
        }

        VerticalScrollDecorator { }
    }
}
