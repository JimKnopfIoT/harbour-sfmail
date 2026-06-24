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
    property string title: qsTr("Inbox")

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

    onStatusChanged: {
        if (status === PageStatus.Active && attachFolders && !_foldersAttached) {
            var acc = accountId > 0 ? accountId : pendingAccountId
            if (acc > 0) {
                _foldersAttached = true
                pageStack.pushAttached(Qt.resolvedUrl("FoldersPage.qml"),
                                       { accountId: acc, accountName: page.title })
            }
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
            title: page.title
            description: emailAgent.synchronizing ? qsTr("Syncing…") : ""
        }

        PullDownMenu {
            MenuItem {
                text: qsTr("Folders")
                visible: (page.accountId > 0 || page.pendingAccountId > 0)
                onClicked: pageStack.push(Qt.resolvedUrl("FoldersPage.qml"),
                                          { accountId: page.accountId > 0 ? page.accountId
                                                                          : page.pendingAccountId,
                                            accountName: page.title })
            }
            MenuItem {
                text: qsTr("Sync")
                visible: page.pendingAccountId > 0 || page.folderAccessor !== null
                onClicked: {
                    var accId = page.pendingAccountId > 0 ? page.pendingAccountId : 0
                    if (accId > 0) emailAgent.synchronizeInbox(accId)
                    else emailAgent.accountsSyncInbox()
                }
            }
            // LAST → very bottom of the pulley (primary action, smallest pull).
            MenuItem {
                text: qsTr("New message")
                onClicked: pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                          { composeAccountId: page.accountId > 0 ? page.accountId
                                                                                 : page.pendingAccountId })
            }
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
            onClicked: pageStack.push(Qt.resolvedUrl("MessagePage.qml"),
                                      { messageId: model.messageId })

            function deleteMessage() {
                // Just the remorse timer (with undo) — the extra confirm dialog
                // was one tap too many.
                var mid = model.messageId
                item.remorseAction(qsTr("Deleting"), function() { emailAgent.deleteMessage(mid) })
            }

            menu: ContextMenu {
                MenuItem {
                    text: model.readStatus ? qsTr("Mark as unread") : qsTr("Mark as read")
                    onClicked: model.readStatus ? emailAgent.markMessageAsUnread(model.messageId)
                                                : emailAgent.markMessageAsRead(model.messageId)
                }
                MenuItem {
                    text: qsTr("Delete")
                    onClicked: item.deleteMessage()
                }
            }

            GlassItem {
                id: unread
                visible: !model.readStatus
                anchors.verticalCenter: parent.verticalCenter
                x: Theme.paddingSmall - width / 2
                color: Theme.highlightColor
            }

            Column {
                anchors.verticalCenter: parent.verticalCenter
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin

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
