import QtQuick 2.6
import Sailfish.Silica 1.0
import Nemo.Email 0.1
import SFMail.Gpg 1.0
import SFMail.Search 1.0
import "../agent"

// Extended search: conditions on sender, recipients, subject and text, joined
// with AND or OR, each one negatable; narrowed by accounts, a date range and
// attachments. Needs the search plugin, which the standard build includes; a
// build without it drops this page, and SearchPage only offers it when the
// plugin is installed.
//
// Like the plain search it reads metadata only: the text of encrypted
// messages stays ciphertext and is not searched, nothing is decrypted.
// The server is asked only on request; whatever it returns is checked against
// the full filter before it is shown (the server never sees the date range or
// the attachment filter).
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    // The account the plain search was opened for; preselected.
    property int accountId: 0

    // Account id → selected. "revision" makes bindings see changes to the map.
    property var _selected: ({})
    property int _revision: 0
    property bool _matchAll: true
    property var _dateFrom: null
    property var _dateTo: null
    property int _attachments: 0
    // "" until a search ran; the code of what keeps the filter from running.
    property string _problem: ""
    property bool _searched: false

    readonly property var _fields: ["from", "to", "subject", "text"]

    function _fieldText(f) {
        switch (f) {
        case "from":    return qsTr("Sender")
        case "to":      return qsTr("Recipient")
        case "subject": return qsTr("Subject")
        case "text":    return qsTr("Text")
        }
        return f
    }

    function _problemText(code) {
        switch (code) {
        case "text-negated": return qsTr("The text cannot be negated — the mail framework only searches for text that is contained.")
        case "text-twice":   return qsTr("Only one text condition is possible.")
        case "nothing":      return qsTr("Add a condition, a date or an attachment filter.")
        case "server-needs-condition": return qsTr("The server needs at least one condition; otherwise it would hand over every message it has.")
        }
        return ""
    }

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

    function _previewText(encrypted, preview) {
        var p = preview ? String(preview) : ""
        if (encrypted || p.indexOf("-----BEGIN PGP MESSAGE-----") === 0)
            return "(" + qsTr("Encrypted") + ")"
        return p
    }

    function _apply() {
        var ids = []
        for (var k in page._selected)
            if (page._selected[k]) ids.push(parseInt(k))
        var conds = []
        for (var i = 0; i < conditions.count; ++i) {
            var c = conditions.get(i)
            conds.push({ field: c.field, negate: c.negate, value: c.value })
        }
        search.accountIds = ids
        search.conditions = conds
        search.matchAll = page._matchAll
        search.dateFrom = page._dateFrom
        search.dateTo = page._dateTo
        search.attachments = page._attachments
    }

    function _runLocal() {
        page._apply()
        page._problem = search.problem(false)
        if (page._problem !== "") return
        page._searched = true
        search.searchLocal()
    }

    function _runRemote() {
        page._apply()
        page._problem = search.problem(true)
        if (page._problem !== "") return
        if (!MailAgent.isOnline()) {
            page._problem = "offline"
            return
        }
        page._searched = true
        search.searchRemote()
    }

    function _pickDate(which) {
        var current = which === "from" ? page._dateFrom : page._dateTo
        var dlg = pageStack.push("Sailfish.Silica.DatePickerDialog",
                                 { date: current ? current : new Date() })
        dlg.accepted.connect(function() {
            if (which === "from") page._dateFrom = dlg.date
            else page._dateTo = dlg.date
        })
    }

    Component.onCompleted: {
        if (page.accountId > 0) {
            var s = {}
            s[page.accountId] = true
            page._selected = s
        }
        conditions.append({ field: "from", negate: false, value: "" })
    }

    Component.onDestruction: search.cancel()

    MailSearch { id: search }
    EmailAccountListModel { id: accountsModel }
    ListModel { id: conditions }   // {field, negate, value}

    SilicaListView {
        id: listView
        anchors.fill: parent
        model: search

        PullDownMenu {
            MenuItem {
                text: qsTr("Search on the server")
                enabled: search.state !== "remote"
                onClicked: page._runRemote()
            }
            MenuItem {
                text: qsTr("Search")
                enabled: search.state !== "remote"
                onClicked: page._runLocal()
            }
        }

        header: Column {
            width: parent.width

            PageHeader { title: qsTr("Extended search") }

            SectionHeader { text: qsTr("Accounts") }
            Repeater {
                model: accountsModel
                TextSwitch {
                    text: model.displayName !== "" ? model.displayName : model.emailAddress
                    // Only when it adds something: a name equal to the address is shown once.
                    description: model.displayName !== "" && model.displayName !== model.emailAddress
                                 ? model.emailAddress : ""
                    checked: page._revision >= 0 && page._selected[model.mailAccountId] === true
                    onClicked: {
                        var s = page._selected
                        s[model.mailAccountId] = checked
                        page._selected = s
                        page._revision++
                    }
                }
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("No account chosen: all accounts are searched.")
            }

            SectionHeader { text: qsTr("Conditions") }
            ComboBox {
                label: qsTr("Match")
                currentIndex: page._matchAll ? 0 : 1
                menu: ContextMenu {
                    MenuItem { text: qsTr("all conditions") }
                    MenuItem { text: qsTr("any condition") }
                }
                onCurrentIndexChanged: page._matchAll = (currentIndex === 0)
            }
            Repeater {
                model: conditions
                Column {
                    width: parent.width
                    Item {
                        width: parent.width
                        height: fieldBox.height
                        ComboBox {
                            id: fieldBox
                            width: parent.width - removeButton.width - Theme.horizontalPageMargin
                            label: qsTr("Field")
                            currentIndex: page._fields.indexOf(model.field)
                            menu: ContextMenu {
                                Repeater {
                                    model: page._fields
                                    MenuItem { text: page._fieldText(modelData) }
                                }
                            }
                            onCurrentIndexChanged: if (currentIndex >= 0)
                                conditions.setProperty(index, "field", page._fields[currentIndex])
                        }
                        IconButton {
                            id: removeButton
                            anchors.right: parent.right
                            anchors.rightMargin: Theme.horizontalPageMargin - Theme.paddingMedium
                            anchors.verticalCenter: parent.verticalCenter
                            icon.source: "image://theme/icon-m-remove"
                            onClicked: conditions.remove(index)
                        }
                    }
                    TextSwitch {
                        automaticCheck: false
                        text: qsTr("Does not contain")
                        checked: model.negate
                        onClicked: conditions.setProperty(index, "negate", !model.negate)
                    }
                    TextField {
                        width: parent.width
                        placeholderText: model.negate ? qsTr("does not contain …") : qsTr("contains …")
                        label: page._fieldText(model.field)
                        text: model.value
                        inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                        onTextChanged: if (text !== model.value)
                            conditions.setProperty(index, "value", text)
                        EnterKey.iconSource: "image://theme/icon-m-search"
                        EnterKey.onClicked: { focus = false; page._runLocal() }
                    }
                }
            }
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Add condition")
                onClicked: conditions.append({ field: "from", negate: false, value: "" })
            }

            SectionHeader { text: qsTr("Narrow down") }
            ValueButton {
                label: qsTr("From date")
                value: page._dateFrom ? Format.formatDate(page._dateFrom, Formatter.DateMedium)
                                      : qsTr("any")
                onClicked: page._pickDate("from")
                onPressAndHold: page._dateFrom = null
            }
            ValueButton {
                label: qsTr("To date")
                value: page._dateTo ? Format.formatDate(page._dateTo, Formatter.DateMedium)
                                    : qsTr("any")
                onClicked: page._pickDate("to")
                onPressAndHold: page._dateTo = null
            }
            ComboBox {
                label: qsTr("Attachments")
                currentIndex: page._attachments
                menu: ContextMenu {
                    MenuItem { text: qsTr("either") }
                    MenuItem { text: qsTr("with attachments") }
                    MenuItem { text: qsTr("without attachments") }
                }
                onCurrentIndexChanged: page._attachments = currentIndex
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Hold a date to clear it. Attachments are only known for messages whose structure has been downloaded.")
            }

            Item { width: 1; height: Theme.paddingLarge }
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Search")
                enabled: search.state !== "remote"
                onClicked: page._runLocal()
            }
            Item { width: 1; height: Theme.paddingMedium }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                visible: text !== ""
                text: page._problem === "offline"
                      ? qsTr("No connection — the server cannot be searched right now.")
                      : page._problemText(page._problem)
            }
            SectionHeader {
                visible: page._searched
                text: qsTr("%n match(es)", "", search.count)
            }
        }

        delegate: ListItem {
            id: item
            contentHeight: col.height + Theme.paddingMedium * 2

            readonly property var _label: Gpg.folderLabel(model.folderId)

            onClicked: {
                if (_label.type === EmailFolder.DraftsFolder)
                    pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                   { fromDraftId: model.messageId,
                                     composeAccountId: model.accountId })
                else if (("" + _label.name) === "Templates")
                    pageStack.push(Qt.resolvedUrl("ComposerPage.qml"),
                                   { fromTemplateId: model.messageId,
                                     composeAccountId: model.accountId })
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
                        text: model.senderName !== "" ? model.senderName : model.senderAddress
                        font.weight: model.read ? Font.Normal : Font.Bold
                        color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                    }
                    Label {
                        id: dateLabel
                        text: Format.formatDate(model.date, Formatter.DateMedium)
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        anchors.bottom: parent.bottom
                    }
                }
                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    text: model.subject !== "" ? model.subject : qsTr("(no subject)")
                    font.pixelSize: Theme.fontSizeSmall
                    color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                }
                Row {
                    width: parent.width
                    spacing: Theme.paddingSmall
                    Label {
                        width: parent.width - folderLabel.width - parent.spacing
                        truncationMode: TruncationMode.Fade
                        text: page._previewText(model.encrypted, model.preview)
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

        footer: Column {
            width: parent.width
            spacing: Theme.paddingMedium
            visible: page._searched
            Item { width: 1; height: Theme.paddingMedium }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                visible: text !== ""
                text: search.state === "local" ? qsTr("Searching…")
                    : search.state === "remote" ? qsTr("Searching on the server…")
                    : search.state === "failed" ? qsTr("The server search did not finish. Not every account type can search on the server.")
                    : ""
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                visible: text !== ""
                text: {
                    var parts = []
                    if (search.truncated)
                        parts.push(qsTr("Only the newest matches are shown — narrow the search to see the rest."))
                    if (search.remainingOnServer > 0)
                        parts.push(qsTr("%n more match(es) on the server were not loaded.", "",
                                        search.remainingOnServer))
                    if (search.skippedAccounts > 0)
                        parts.push(qsTr("%n account(s) cannot search on the server.", "",
                                        search.skippedAccounts))
                    if (search.failedAccounts > 0 && search.state !== "failed")
                        parts.push(qsTr("The server search failed for %n account(s).", "",
                                        search.failedAccounts))
                    return parts.join(" ")
                }
            }
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: search.state !== "remote"
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

        VerticalScrollDecorator { }
    }
}
