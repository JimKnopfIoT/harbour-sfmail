import QtQuick 2.6
import Sailfish.Silica 1.0
import Nemo.Email 0.1
import SFMail.Gpg 1.0
import "../agent"

// Searching one account, across all of its folders: sender, subject and
// message text. What is stored here is searched as you type; the server is
// only asked when the user says so, because every question to it is a round
// trip per folder and fetches the headers of what it finds.
//
// The search itself is the mail framework's: the list model filters the store
// by sender and subject, and a search action looks into the stored message
// text. On the server the same terms become an IMAP SEARCH (FROM / SUBJECT,
// or BODY). Nothing here syncs a folder, so nothing stored can be lost by
// searching.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property int accountId: 0
    property string accountName: ""

    property string searchText: ""
    // The term the list currently shows results for.
    property string _term: ""
    // Server search: "" (not asked), "busy", "done", "failed", "offline".
    property string _remoteState: ""
    property string _remoteTerm: ""

    readonly property int _minLength: 2

    // Kept on the page: the accessor is created for this page and would be
    // collected otherwise.
    property var _accessor: page.accountId > 0
                            ? MailAgent.accountWideSearchAccessor(page.accountId) : null

    function _folderText(f) {
        switch (f.type) {
        case EmailFolder.InboxFolder:  return qsTr("Inbox")
        case EmailFolder.OutboxFolder: return qsTr("Outbox")
        case EmailFolder.SentFolder:   return qsTr("Sent")
        case EmailFolder.DraftsFolder: return qsTr("Drafts")
        case EmailFolder.TrashFolder:  return qsTr("Trash")
        case EmailFolder.JunkFolder:   return qsTr("Junk")
        default: return f.name ? ("" + f.name) : ""
        }
    }

    // Same rule as the message list: the stored preview of an encrypted
    // message is the armour of its ciphertext.
    function _previewText(encrypted, preview) {
        var p = preview ? String(preview) : ""
        if (encrypted || p.indexOf("-----BEGIN PGP MESSAGE-----") === 0)
            return "(" + qsTr("Encrypted") + ")"
        return p
    }

    function _runLocal() {
        var t = page.searchText.trim()
        if (t.length < page._minLength) t = ""
        if (t === page._term) return
        page._term = t
        page._remoteState = ""
        messageModel.searchOn = EmailMessageListModel.Local
        // An empty term empties the list (and cancels what is still running).
        messageModel.setSearch(t)
        console.log("[search] local", t.length, "chars")
    }

    function _runRemote() {
        if (page._term === "") return
        if (!MailAgent.isOnline()) {
            page._remoteState = "offline"
            return
        }
        page._remoteTerm = page._term
        page._remoteState = "busy"
        // With searchOn Remote the model leaves the local hits in place and
        // adds the server's when they arrive.
        messageModel.searchOn = EmailMessageListModel.Remote
        messageModel.setSearch(page._term)
        messageModel.searchOn = EmailMessageListModel.Local
        remoteTimeout.restart()
        console.log("[search] remote asked")
    }

    onSearchTextChanged: typingTimer.restart()

    Timer {
        id: typingTimer
        interval: 400
        onTriggered: page._runLocal()
    }

    // A server that never answers (no search support, a lost connection)
    // must not leave "Searching…" standing forever.
    Timer {
        id: remoteTimeout
        interval: 90000
        onTriggered: {
            if (page._remoteState === "busy") {
                console.warn("[search] remote: no answer")
                page._remoteState = "failed"
            }
        }
    }

    Connections {
        target: MailAgent
        onSearchCompleted: {
            if (!isRemote || search !== page._remoteTerm || page._remoteState !== "busy")
                return
            remoteTimeout.stop()
            page._remoteState = status === EmailAgent.SearchDone ? "done" : "failed"
            console.log("[search] remote finished, status", status,
                        "remaining", remainingMessagesOnRemote)
        }
    }

    Component.onDestruction: {
        if (page._term !== "") messageModel.cancelSearch()
    }

    EmailMessageListModel {
        id: messageModel
        folderAccessor: page._accessor
        sortBy: EmailMessageListModel.Time
        searchOn: EmailMessageListModel.Local
        searchFrom: true
        searchSubject: true
        searchBody: true
        searchRecipients: false
        searchLimit: 100
        limit: 100
    }

    SilicaListView {
        id: listView
        anchors.fill: parent
        model: messageModel

        header: Column {
            width: parent.width
            PageHeader {
                title: qsTr("Search")
                description: page.accountName
            }
            SearchField {
                width: parent.width
                placeholderText: qsTr("Sender, subject or text")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                // The text has to land on the page: a header is its own
                // component, nothing outside it can read an id declared here.
                onTextChanged: page.searchText = text
                Component.onCompleted: forceActiveFocus()
            }
        }

        PullDownMenu {
            visible: page._term !== ""
            MenuItem {
                text: qsTr("Search on the server")
                enabled: page._remoteState !== "busy"
                onClicked: page._runRemote()
            }
        }

        onAtYEndChanged: if (atYEnd && messageModel.canFetchMore) messageModel.limit += 50

        delegate: ListItem {
            id: item
            contentHeight: col.height + Theme.paddingMedium * 2

            readonly property var _label: Gpg.folderLabel(model.folderId)

            onClicked: {
                if (_label.type === EmailFolder.DraftsFolder)
                    pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                   { fromDraftId: model.messageId,
                                     composeAccountId: page.accountId })
                else if (("" + _label.name) === "Templates")
                    pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                   { fromTemplateId: model.messageId,
                                     composeAccountId: page.accountId })
                else
                    pageStack.push(Qt.resolvedUrl("MessagePage.qml"),
                                   { messageId: model.messageId })
            }

            Column {
                id: col
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
                        text: Format.formatDate(model.qDateTime, Formatter.DateMedium)
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
                        width: parent.width - folderLabel.width - parent.spacing
                        truncationMode: TruncationMode.Fade
                        text: page._previewText(model.isEncrypted, model.preview)
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                    }
                    Label {
                        id: folderLabel
                        text: page._folderText(item._label)
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.highlightColor
                        anchors.bottom: parent.bottom
                    }
                }
            }
        }

        // What the server search is doing, and what the search cannot do.
        footer: Column {
            width: parent.width
            spacing: Theme.paddingMedium
            visible: page._term !== ""
            Item { width: 1; height: Theme.paddingMedium }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                visible: messageModel.count === 0 && page._remoteState !== "busy"
                text: qsTr("No matches.")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                visible: text !== ""
                text: page._remoteState === "busy" ? qsTr("Searching on the server…")
                    : page._remoteState === "offline" ? qsTr("No connection — the server cannot be searched right now.")
                    : page._remoteState === "failed" ? qsTr("The server search did not finish. Not every account type can search on the server.")
                    : page._remoteState === "done"
                      ? (messageModel.searchRemainingOnRemote > 0
                         ? qsTr("Server searched. %n more match(es) on the server were not loaded.", "",
                                messageModel.searchRemainingOnRemote)
                         : qsTr("Server searched."))
                    : ""
            }
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page._remoteState !== "busy"
                text: qsTr("Search on the server")
                onClicked: page._runRemote()
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("The text of encrypted messages cannot be searched; they are found by sender and subject.")
            }
            Item { width: 1; height: Theme.paddingLarge }
        }

        ViewPlaceholder {
            enabled: messageModel.count === 0 && page._term === ""
            text: qsTr("Search this account")
            hintText: qsTr("Sender, subject and message text, in all folders")
        }

        VerticalScrollDecorator { }
    }
}
