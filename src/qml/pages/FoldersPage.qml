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
        // Our own local Templates folder (custom type, fixed English store name).
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
            title: qsTr("Folders")
            description: page.accountName !== "" ? page.accountName
                         : (emailAgent.synchronizing ? qsTr("Syncing…") : "")
        }

        // Templates aren't a server folder (they live locally, so a folder sync
        // can't delete them) — surface them as a tappable entry AT THE BOTTOM of
        // the folder list (footer), styled like a plain folder row (no icon).
        footer: BackgroundItem {
            id: templatesEntry
            width: listView.width
            visible: page.accountId > 0
            height: Theme.itemSizeSmall
            onClicked: pageStack.push(Qt.resolvedUrl("TemplatesPage.qml"),
                                      { accountId: page.accountId,
                                        accountName: page.accountName })
            Label {
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - x - Theme.horizontalPageMargin
                truncationMode: TruncationMode.Fade
                text: qsTr("Templates")
                color: templatesEntry.highlighted ? Theme.highlightColor : Theme.primaryColor
            }
        }

        PullDownMenu {
            // Read-only: pulls the folder list + new mail from the server. Never
            // deletes anything server-side.
            MenuItem {
                text: qsTr("Sync folders")
                onClicked: emailAgent.synchronize(page.accountId)
            }
            // Templates live in a local folder that the folder list above may not
            // surface on every account type — open them directly.
            MenuItem {
                text: qsTr("Templates")
                visible: page.accountId > 0
                onClicked: pageStack.push(Qt.resolvedUrl("TemplatesPage.qml"),
                                          { accountId: page.accountId,
                                            accountName: page.accountName })
            }
        }

        delegate: ListItem {
            id: folderItem
            // Hide the old per-account "Templates" folder left over from
            // 0.3.93/0.3.94: templates now live in a local folder reached via
            // the footer entry, so this stale folder is just a confusing second
            // entry that can't be used (some accounts showed two "Templates").
            readonly property bool _oldTemplates: ("" + model.folderName) === "Templates"
            visible: !_oldTemplates
            contentHeight: _oldTemplates ? 0 : Theme.itemSizeSmall
            // Use the accessor the model itself built for this row — it carries the
            // correct QMailMessageKey. Standard folders (Sent/Drafts/Trash/Outbox)
            // are filtered by message STATUS, not by a physical folder id. That is
            // essential for POP3 accounts, where all of those messages live in ONE
            // physical local folder: filtering by folder id would show the same mail
            // in every folder view. Building the accessor from the folder id alone
            // (accessorFromFolderId) bypasses that key and causes exactly that. This
            // matches how the stock mail app navigates folders.
            onClicked: pageStack.push(Qt.resolvedUrl("MessageListPage.qml"),
                                      { folderAccessor: folderModel.folderAccessor(index),
                                        title: _folderName(model.folderType, model.folderName),
                                        accountId: page.accountId,
                                        folderId: model.folderId,
                                        folderType: model.folderType,
                                        isTemplates: ("" + model.folderName) === "Templates" })

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
