import QtQuick 2.6
import Sailfish.Silica 1.0
import Nemo.Email 0.1
import SFMail.Gpg 1.0

// Nachrichtenliste eines Ordners. Befüllung über einen FolderAccessor (vom
// EmailAgent). Falls der Posteingang beim Öffnen noch nicht bekannt war, wird
// pendingAccountId gesetzt und wir warten auf standardFoldersCreated.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property var folderAccessor: null
    property int pendingAccountId: 0
    property int accountId: 0           // mailbox account (0 = combined/unknown)
    property int folderId: 0            // real folder id (from FoldersPage; 0 = inbox/combined)
    property int folderType: 0         // EmailFolder.*Folder (from FoldersPage; 0 = inbox/combined)
    property bool isTemplates: false    // this is our local Templates folder
    // Standard-folder specifics: a draft opens the composer for editing; the Trash
    // view offers "Empty Trash".
    property bool isDrafts: folderType === EmailFolder.DraftsFolder
    property bool isTrash: folderType === EmailFolder.TrashFolder
    property string title: qsTr("Inbox")
    property bool _folderRetrieved: false

    // Human-readable message size: < 1 MB in kB, ≥ 1 MB in MB.
    function _fmtSize(bytes) {
        var b = Number(bytes) || 0
        if (b >= 1048576) return (b / 1048576).toFixed(1) + " MB"
        return Math.max(1, Math.round(b / 1024)) + " kB"
    }
    // Attach the account's folder list as a forward page (swipe left → folders),
    // like the Jolla Mail app. Only the inbox sets this; folder views don't.
    property bool attachFolders: false
    property bool _foldersAttached: false

    // Multi-select: tap the pulley "Select messages" → each tap toggles a row; then
    // Delete / Mark read on all selected at once (nemo model selection API).
    property bool _selectMode: false
    function _enterSelect() { messageModel.deselectAllMessages(); page._selectMode = true }
    function _exitSelect()  { messageModel.deselectAllMessages(); page._selectMode = false }

    // Deleting a single row runs through the page's RemorsePopup, never through
    // a RemorseItem inside the delegate. A RemorseItem is a child of its row,
    // and Silica executes a running one when that child is destroyed
    // (RemorseItem.qml, Component.onDestruction). Deleting one message rebuilds
    // the list, so the neighbour's countdown was torn down together with its row
    // and fired on the way out — that is how a delete the user had tapped to
    // cancel went through anyway. Reproduced on the Gemini: both touched mails
    // ended up in Trash, one of them against an explicit cancel.
    //
    // A page-level popup has only one slot, so the ids are collected instead of
    // overwriting each other: a second delete during a running countdown would
    // otherwise silently drop the first. Cancel drops the whole batch, which is
    // what the bar says ("Deleting 3").
    property var _pendingDeletes: []

    // Leaving the foreground aborts a running countdown at once, instead of only
    // suppressing it when it expires. Suppressing at expiry was not enough:
    // minimising the app and coming back inside the four seconds left the
    // countdown running, and it fired in the user's face on return (measured on
    // the Gemini). Cancelling here makes the bar disappear the moment the app
    // goes away, so nothing is counting when the user comes back.
    readonly property bool appForeground: Qt.application.active
    onAppForegroundChanged: {
        if (!appForeground && remorse.pending) {
            remorse.cancel()
        }
    }


    // Moving, offered in every folder rather than only in Trash. Until now the
    // app could delete a message but not put it back, so an accidental delete
    // was final as far as this app was concerned.
    //
    // No remorse on a move: it is reversible by moving back, and the row action
    // already sits behind a context menu.
    //
    // The account comes from the message, not from the page: in the combined
    // inbox page.accountId is 0, and the folder list needs a real account.
    function _moveMessage(mid) {
        var acc = emailAgent.accountIdForMessage(mid)
        var picker = pageStack.push(
                    Qt.resolvedUrl("FolderPickerPage.qml"),
                    { accountId: acc > 0 ? acc : page.accountId,
                      excludeFolderId: emailAgent.folderIdForMessage(mid) })
        picker.folderPicked.connect(function(folderId) {
            emailAgent.moveMessage(mid, folderId)
        })
    }

    // The batch move needs one account for the folder list, so it is only
    // offered where the page knows one.
    function _moveSelected() {
        var picker = pageStack.push(
                    Qt.resolvedUrl("FolderPickerPage.qml"),
                    { accountId: page.accountId,
                      excludeFolderId: page.folderId,
                      messageCount: messageModel.selectedMessageCount })
        picker.folderPicked.connect(function(folderId) {
            messageModel.moveSelectedMessages(folderId)
            // Same reasoning as the batch delete: do not call _exitSelect(),
            // whose extra deselectAllMessages() touches the selection model
            // right after the native call reorganised it.
            page._selectMode = false
        })
    }

    function _queueDelete(mid) {
        var ids = page._pendingDeletes.slice()
        ids.push(mid)
        page._pendingDeletes = ids
        remorse.execute(ids.length > 1 ? qsTr("Deleting %1").arg(ids.length)
                                       : qsTr("Deleting"),
                        function() {
                            var pending = page._pendingDeletes
                            page._pendingDeletes = []
                            // Two ways out, both of which must abort rather
                            // than commit. Leaving the page: Silica runs a
                            // remorse on PageStatus.Deactivating. Leaving the
                            // app: the page is destroyed without ever going
                            // through Deactivating, and minimising does not
                            // change the page at all - the countdown would just
                            // run out behind the user's back. Both were
                            // reproduced on the Gemini.
                            if (page.status !== PageStatus.Active || !Qt.application.active) {
                                return
                            }
                            for (var i = 0; i < pending.length; ++i) {
                                emailAgent.deleteMessage(pending[i])
                            }
                        })
    }

    onStatusChanged: {
        if (status === PageStatus.Active && attachFolders && !_foldersAttached) {
            var acc = accountId > 0 ? accountId : pendingAccountId
            if (acc > 0) {
                _foldersAttached = true
                pageStack.pushAttached(Qt.resolvedUrl("FoldersPage.qml"),
                                       { accountId: acc, accountName: page.title })
            }
        }
        // A non-inbox folder (opened from FoldersPage) is only synced on demand:
        // the app's normal sync fetches the inbox only, so folders like Junk/Sent
        // stay empty until we retrieve them from the server. Do it once on open, so
        // e.g. mail another client filed into Junk actually shows up here.
        if (status === PageStatus.Active && !_folderRetrieved && !page.isTemplates
                && page.folderId > 0 && page.accountId > 0) {
            _folderRetrieved = true
            emailAgent.retrieveMessageList(page.accountId, page.folderId, 40)
        }
    }
    // Bumped when the "verified signed" memory changes, to re-evaluate the
    // signature badges in the list (PGP signatures are only known post-decrypt).
    property int _sigTick: 0

    Connections {
        target: Gpg
        onSignedChanged: page._sigTick++
    }

    EmailAgent {
        id: emailAgent
        onStandardFoldersCreated: {
            if (page.pendingAccountId > 0 && accountId === page.pendingAccountId) {
                var inboxId = emailAgent.inboxFolderId(page.pendingAccountId)
                if (inboxId > 0) {
                    page.folderAccessor = emailAgent.accessorFromFolderId(inboxId)
                    page.pendingAccountId = 0
                }
            }
        }
    }

    EmailMessageListModel {
        id: messageModel
        folderAccessor: page.folderAccessor
        sortBy: EmailMessageListModel.Time
        limit: 100
        onFolderAccessorChanged: limit = 100
    }

    SilicaListView {
        id: listView
        anchors.fill: parent
        model: messageModel

        header: PageHeader {
            title: page._selectMode ? qsTr("Selected: %1").arg(messageModel.selectedMessageCount)
                                    : page.title
            description: page._selectMode ? qsTr("Tap messages to select")
                       : emailAgent.synchronizing ? qsTr("Syncing…") : ""
        }

        PullDownMenu {
            // === Selection mode: act on all selected at once ===
            MenuItem {
                visible: page._selectMode
                text: qsTr("Cancel")
                onClicked: page._exitSelect()
            }
            MenuItem {
                visible: page._selectMode
                text: messageModel.selectedMessageCount < messageModel.count
                      ? qsTr("Select all") : qsTr("Deselect all")
                onClicked: messageModel.selectedMessageCount < messageModel.count
                           ? messageModel.selectAllMessages() : messageModel.deselectAllMessages()
            }
            MenuItem {
                visible: page._selectMode && !page.isTemplates
                enabled: messageModel.selectedMessageCount > 0
                text: messageModel.unreadMailsSelected ? qsTr("Mark selected as read")
                                                       : qsTr("Mark selected as unread")
                onClicked: {
                    if (messageModel.unreadMailsSelected) messageModel.markAsReadSelectedMessages()
                    else messageModel.markAsUnReadSelectedMessages()
                    page._exitSelect()
                }
            }
            MenuItem {
                visible: page._selectMode && page.accountId > 0
                enabled: messageModel.selectedMessageCount > 0
                text: qsTr("Move selected…")
                onClicked: page._moveSelected()
            }
            MenuItem {
                visible: page._selectMode
                enabled: messageModel.selectedMessageCount > 0
                text: qsTr("Delete selected")
                onClicked: {
                    var n = messageModel.selectedMessageCount
                    remorse.execute(qsTr("Deleting %1").arg(n), function() {
                        // This execute() replaced whatever single-row deletes
                        // were queued on the same popup; drop them rather than
                        // letting them ride along with a later delete.
                        page._pendingDeletes = []
                        // Leaving the page aborts the countdown. Silica does
                        // the opposite by design — RemorsePopup.qml executes
                        // the action on PageStatus.Deactivating ("if the page
                        // is changed then execute immediately") — so going
                        // back to the account overview mid-countdown used to
                        // delete the mails instead of sparing them. Only the
                        // swipe on the remorse bar is meant to commit early.
                        if (page.status !== PageStatus.Active || !Qt.application.active) {
                            return
                        }
                        messageModel.deleteSelectedMessages()
                        // deleteSelectedMessages() already clears the selection.
                        // Do NOT call _exitSelect() here: its extra
                        // deselectAllMessages() touches the selection model right
                        // after the native batch delete tore it down, which crashes
                        // intermittently (SIGSEGV at 0x2a, works on the 2nd try).
                        // Just leave select mode.
                        page._selectMode = false
                    })
                }
            }

            // === Normal mode ===
            MenuItem {
                text: qsTr("Folders")
                visible: !page._selectMode && (page.accountId > 0 || page.pendingAccountId > 0)
                onClicked: pageStack.push(Qt.resolvedUrl("FoldersPage.qml"),
                                          { accountId: page.accountId > 0 ? page.accountId
                                                                          : page.pendingAccountId,
                                            accountName: page.title })
            }
            MenuItem {
                text: qsTr("Templates")
                // A single, real account is needed to scope templates.
                visible: !page._selectMode && (page.accountId > 0 || page.pendingAccountId > 0) && !page.isTemplates
                onClicked: pageStack.push(Qt.resolvedUrl("TemplatesPage.qml"),
                                          { accountId: page.accountId > 0 ? page.accountId
                                                                          : page.pendingAccountId,
                                            accountName: page.title })
            }
            MenuItem {
                text: qsTr("Sync")
                // Templates are a local folder — nothing to fetch from the server.
                visible: !page._selectMode && !page.isTemplates
                         && (page.pendingAccountId > 0 || page.folderAccessor !== null)
                onClicked: {
                    // In a specific folder → sync THAT folder from the server;
                    // otherwise sync the inbox (single account or all).
                    if (page.folderId > 0 && page.accountId > 0) {
                        emailAgent.retrieveMessageList(page.accountId, page.folderId, 40)
                    } else {
                        var accId = page.pendingAccountId > 0 ? page.pendingAccountId : 0
                        if (accId > 0) emailAgent.synchronizeInbox(accId)
                        else emailAgent.accountsSyncInbox()
                    }
                }
            }
            MenuItem {
                // Enter multi-select. Not for the Templates folder (tap = compose).
                text: qsTr("Select messages")
                visible: !page._selectMode && !page.isTemplates && messageModel.count > 0
                onClicked: page._enterSelect()
            }
            MenuItem {
                // Mark every message in this folder as read (handy after a burst of
                // test mail). Not for the Templates folder.
                text: qsTr("Mark all as read")
                visible: !page._selectMode && !page.isTemplates && messageModel.count > 0
                onClicked: messageModel.markAllMessagesAsRead()
            }
            MenuItem {
                // Empty the Trash in one go (permanent). Confirmed first.
                text: qsTr("Empty Trash")
                visible: !page._selectMode && page.isTrash && messageModel.count > 0
                onClicked: {
                    var dlg = pageStack.push(Qt.resolvedUrl("ConfirmDialog.qml"),
                                             { question: qsTr("Empty Trash?"),
                                               warning: qsTr("All messages in Trash will be permanently deleted."),
                                               acceptText: qsTr("Empty") })
                    dlg.accepted.connect(function() {
                        messageModel.selectAllMessages()
                        messageModel.deleteSelectedMessages()
                    })
                }
            }
            // LAST → very bottom of the pulley (primary action, smallest pull).
            MenuItem {
                text: qsTr("New message")
                visible: !page._selectMode
                onClicked: pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                          { composeAccountId: page.accountId > 0 ? page.accountId
                                                                                 : page.pendingAccountId })
            }
        }

        // Remorse for batch delete and for single-row deletes (a RemorsePopup
        // covers the whole view and, unlike a per-row RemorseItem, outlives the
        // rows — see _queueDelete above). Tapping it cancels, so the queued ids
        // have to go with it.
        RemorsePopup {
            id: remorse
            onCanceled: page._pendingDeletes = []
        }

        onAtYEndChanged: if (atYEnd && messageModel.canFetchMore) messageModel.limit += 50

        section {
            property: "timeSection"
            delegate: SectionHeader {
                text: Format.formatDate(section, Formatter.TimepointSectionRelative)
            }
        }

        delegate: ListItem {
            id: item
            contentHeight: Theme.itemSizeMedium
            // A template opens the composer (prefilled) and stays for reuse; a draft
            // opens the composer to keep editing it; everything else opens the reader.
            // In select mode, a tap toggles this row's selection instead.
            onClicked: {
                if (page._selectMode) {
                    if (model.selected) messageModel.deselectMessage(index)
                    else messageModel.selectMessage(index)
                    return
                }
                if (page.isTemplates)
                    pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                   { fromTemplateId: model.messageId,
                                     composeAccountId: page.accountId })
                else if (page.isDrafts)
                    pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                   { fromDraftId: model.messageId,
                                     composeAccountId: page.accountId })
                else
                    pageStack.push(Qt.resolvedUrl("MessagePage.qml"),
                                   { messageId: model.messageId })
            }

            function deleteMessage() {
                // Just the remorse timer (with undo) — the extra confirm dialog
                // was one tap too many.
                page._queueDelete(model.messageId)
            }

            menu: ContextMenu {
                // In Drafts, editing is the point — a read/unread toggle is
                // meaningless there, so offer "Edit" instead.
                MenuItem {
                    visible: page.isDrafts
                    text: qsTr("Edit")
                    onClicked: pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                              { fromDraftId: model.messageId,
                                                composeAccountId: page.accountId })
                }
                MenuItem {
                    visible: !page.isDrafts
                    text: model.readStatus ? qsTr("Mark as unread") : qsTr("Mark as read")
                    onClicked: model.readStatus ? emailAgent.markMessageAsUnread(model.messageId)
                                                : emailAgent.markMessageAsRead(model.messageId)
                }
                MenuItem {
                    text: qsTr("Move to folder…")
                    onClicked: page._moveMessage(model.messageId)
                }
                MenuItem {
                    text: qsTr("Delete")
                    onClicked: item.deleteMessage()
                }
            }

            GlassItem {
                id: unread
                visible: !model.readStatus && !page._selectMode
                anchors.verticalCenter: parent.verticalCenter
                x: Theme.paddingSmall - width / 2
                color: Theme.highlightColor
            }

            // Selection indicator (right edge) — only in select mode.
            Icon {
                id: selCheck
                visible: page._selectMode
                anchors.verticalCenter: parent.verticalCenter
                anchors.right: parent.right
                anchors.rightMargin: Theme.horizontalPageMargin
                source: "image://theme/icon-m-acknowledge?"
                        + (model.selected ? Theme.highlightColor : Theme.secondaryColor)
                opacity: model.selected ? 1.0 : 0.3
            }

            Column {
                anchors.verticalCenter: parent.verticalCenter
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                       - (page._selectMode ? Theme.iconSizeMedium + Theme.paddingMedium : 0)

                Row {
                    width: parent.width
                    spacing: Theme.paddingSmall
                    Label {
                        width: parent.width - dateLabel.width - parent.spacing
                        truncationMode: TruncationMode.Fade
                        text: model.senderDisplayName !== "" ? model.senderDisplayName
                                                             : model.senderEmailAddress
                        font.weight: model.readStatus ? Font.Normal : Font.Bold
                        color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                    }
                    Label {
                        id: dateLabel
                        text: Format.formatDate(model.qDateTime, Formatter.TimeValue)
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        anchors.bottom: parent.bottom
                    }
                }

                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    text: model.parsedSubject !== "" ? model.parsedSubject : qsTr("(no subject)")
                    font.pixelSize: Theme.fontSizeSmall
                    color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                }

                Row {
                    width: parent.width
                    spacing: Theme.paddingSmall
                    Label {
                        width: parent.width - icons.width - parent.spacing
                        truncationMode: TruncationMode.Fade
                        text: model.preview
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                    }
                    Row {
                        id: icons
                        spacing: Theme.paddingSmall
                        anchors.bottom: parent.bottom
                        // Total message size next to the attachment clip. The list
                        // size is what QMF has stored locally; an undownloaded
                        // attachment isn't counted yet, so flag "(header only)" when
                        // the mail has an attachment but the stored size is still tiny.
                        Label {
                            text: page._fmtSize(model.size)
                                  + (model.hasAttachments && model.size < 102400
                                     ? " " + qsTr("(header only)") : "")
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryColor
                            anchors.bottom: parent.bottom
                        }
                        Image {
                            visible: model.isEncrypted
                            source: "image://theme/icon-s-secure?" + Theme.highlightColor
                            sourceSize.height: Theme.iconSizeExtraSmall
                        }
                        Image {
                            // QMF flags multipart/signed; our memory adds PGP
                            // signatures that were only revealed by decrypting.
                            visible: model.hasSignature
                                     || (page._sigTick >= 0 && Gpg.isSigned(model.messageId))
                            source: "image://theme/icon-s-certificates?" + Theme.highlightColor
                            sourceSize.height: Theme.iconSizeExtraSmall
                        }
                        Image {
                            visible: model.hasAttachments
                            source: "image://theme/icon-s-attach?" + Theme.secondaryColor
                            sourceSize.height: Theme.iconSizeExtraSmall
                        }
                    }
                }
            }
        }

        ViewPlaceholder {
            enabled: messageModel.count === 0 && !emailAgent.synchronizing
            text: page.pendingAccountId > 0 ? qsTr("Loading inbox…") : qsTr("No messages")
            hintText: qsTr("Pull down to sync")
        }

        VerticalScrollDecorator { }
    }
}
