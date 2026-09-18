import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// Why accounts sometimes go quiet, and where that comes from.
//
// Fetching mail is done by a system service that every mail application on the
// device shares; this app hands it requests and displays what comes back. When
// that service stops opening connections, no application can fix it from the
// outside — but the user is left staring at an empty mailbox in OUR window, so
// this page states plainly what happened, shows what the app was told, and
// names the remedy. See the recorder in main.cpp and mailPushSummary() in the
// crypto plugin for where the two halves of the evidence come from.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property var _push: ({})
    property var _lines: []
    property string _note: ""

    function _reload() {
        _push = Gpg.mailPushSummary()
        _lines = DebugLog.syncIssues()
    }

    Component.onCompleted: _reload()
    onStatusChanged: if (status === PageStatus.Active) _reload()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                text: qsTr("Clear recorded lines")
                visible: page._lines.length > 0
                onClicked: { DebugLog.clearSyncIssues(); page._reload() }
            }
            MenuItem {
                text: qsTr("Refresh")
                onClicked: page._reload()
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader { title: qsTr("When mail stops arriving") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("If your accounts fall silent — nothing new for hours or days, while the "
                           + "same mailbox clearly has new messages when you look at it elsewhere — "
                           + "this page explains what is happening.")
            }

            // Says it before anything else: this is a workaround for somebody
            // else's fault, kept only until the fix ships.
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                font.bold: true
                color: Theme.highlightColor
                text: qsTr("This page is a temporary fix. The fault is not in this app, and the "
                           + "correction for it already exists in the operating system. As soon as "
                           + "a system update brings a working fix to this device, this page and "
                           + "its button will be removed from the app.")
            }

            SectionHeader { text: qsTr("Where this comes from") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: qsTr("Collecting mail is not this app's work. Every mail application on this "
                           + "device asks the same system service to talk to your mail servers; this "
                           + "app only asks it for messages and shows what comes back.\n\n"
                           + "That service limits how many mailboxes may be watched for new mail at "
                           + "the same time, and it miscounts them: a connection that drops does not "
                           + "reliably give its reservation back. After a few days the count has crept "
                           + "past the limit, and from then on the service refuses to open any such "
                           + "connection at all — for every account at once. An account that waits for "
                           + "new mail to be announced, rather than fetching on a timer, then receives "
                           + "nothing until the service is restarted.\n\n"
                           + "No application can prevent this or reset that count. What this app can "
                           + "do is tell you, instead of leaving you with an empty mailbox and no "
                           + "explanation.")
            }

            SectionHeader { text: qsTr("On this device") }

            DetailItem {
                label: qsTr("Mail accounts")
                value: page._push.accounts !== undefined ? page._push.accounts : "–"
            }
            DetailItem {
                label: qsTr("Mailboxes watched")
                // The number the user is measured against, and the ceiling it is
                // measured against — both named, so the report stands on its own.
                value: page._push.pushFolders !== undefined
                       ? qsTr("%1 of at most %2").arg(page._push.pushFolders).arg(page._push.ceiling)
                       : "–"
            }
            DetailItem {
                label: qsTr("Announced mail only")
                value: page._push.pushOnlyAccounts !== undefined ? page._push.pushOnlyAccounts : "–"
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Every watched mailbox holds one connection. The limit of %1 is built into "
                           + "the system service and cannot be changed. It is counted across all "
                           + "accounts together, which is why one account running out takes the "
                           + "others down with it. Accounts listed as \"announced mail only\" have no "
                           + "timed fetch to fall back on.")
                      .arg(page._push.ceiling !== undefined ? page._push.ceiling : 10)
            }

            SectionHeader { text: qsTr("What this app was told") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                visible: page._lines.length === 0
                text: qsTr("Nothing recorded. These are the failures the mail service reports back to "
                           + "this app; they are kept even while debug logging is off, because a fault "
                           + "like this is noticed long after it happened.")
            }

            Repeater {
                model: page._lines
                Label {
                    x: Theme.horizontalPageMargin
                    width: col.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeTiny
                    font.family: "monospace"
                    color: Theme.highlightColor
                    text: modelData
                }
            }

            SectionHeader { text: qsTr("What helps") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: qsTr("The count lives in that service and nowhere else, so restarting it is "
                           + "the whole remedy. Nothing is lost: your mail sits in the message store "
                           + "and the service comes straight back up. A transfer running at that "
                           + "moment is picked up again afterwards.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Restart the mail service")
                onClicked: {
                    if (MailService.restart())
                        page._note = qsTr("Restarted. Give it a moment, then fetch mail again.")
                    else
                        page._note = qsTr("Could not restart it: %1").arg(MailService.lastError())
                }
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                visible: page._note !== ""
                text: page._note
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: qsTr("Restarting the device does the same thing.\n\n"
                           + "If it keeps coming back, give at least one account a fetch interval in "
                           + "the system's account settings instead of letting it wait for announced "
                           + "mail alone. A timed fetch does not use these connections and keeps "
                           + "working when the service refuses them.\n\n"
                           + "Should the button above not get through, the same can be done from a "
                           + "terminal:")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                font.family: "monospace"
                color: Theme.highlightColor
                text: "systemctl --user restart messageserver5"
            }

            SectionHeader { text: qsTr("Already repaired at the source") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: qsTr("The fault is known and has already been corrected in the operating "
                           + "system's own source code (bug JB#64979, September 2026): the counting "
                           + "was dropped altogether, and a device now uses as many watched mailboxes "
                           + "as it can get instead of refusing all of them. That correction is not in "
                           + "the system version running here, so it should reach this device with a "
                           + "future Sailfish OS update — and this page becomes pointless.")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.primaryColor
                linkColor: Theme.highlightColor
                textFormat: Text.StyledText
                onLinkActivated: Qt.openUrlExternally(link)
                text: "<a href=\"https://github.com/sailfishos/messagingframework/commit/"
                      + "95540bc1efb765f3d8f08025d31e90b3efaa2c05\">"
                      + "sailfishos/messagingframework 95540bc</a>"
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeTiny
                color: Theme.secondaryColor
                text: "https://github.com/sailfishos/messagingframework/commit/95540bc"
            }
        }
        VerticalScrollDecorator { }
    }
}
