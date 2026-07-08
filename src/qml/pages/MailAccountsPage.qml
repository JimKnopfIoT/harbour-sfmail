import QtQuick 2.6
import Sailfish.Silica 1.0
import Nemo.Email 0.1
import SFMail.Gpg 1.0

// Startseite: Liste der E-Mail-Konten + kombinierter Posteingang. Klick öffnet
// den Posteingang des Kontos. Jede Seite hält ihre eigenen Nemo.Email-Objekte
// (kein Singleton; greifen alle auf dieselbe zentrale QMF-Datenbank zu).
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    // Bumped to re-evaluate which account is the default sender (highlighted).
    property int _defaultTick: 0
    Connections {
        target: Gpg
        onDefaultAccountChanged: page._defaultTick++
    }

    EmailAgent {
        id: emailAgent
        onError: console.warn("[sfmail] sync error account", accountId, "err", syncError)
    }

    EmailAccountListModel {
        id: accountsModel
    }

    function openInbox(accountId, name) {
        var inboxId = emailAgent.inboxFolderId(accountId)
        if (inboxId > 0) {
            pageStack.push(Qt.resolvedUrl("MessageListPage.qml"),
                           { folderAccessor: emailAgent.accessorFromFolderId(inboxId),
                             title: name, accountId: accountId, attachFolders: true })
        } else {
            // Standardordner noch nicht bekannt — erst Inbox synchronisieren.
            emailAgent.synchronizeInbox(accountId)
            pageStack.push(Qt.resolvedUrl("MessageListPage.qml"),
                           { pendingAccountId: accountId, title: name, accountId: accountId,
                             attachFolders: true })
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height

        PullDownMenu {
            MenuItem {
                text: qsTr("About")
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }
            MenuItem {
                text: qsTr("PGP keys")
                onClicked: pageStack.push(Qt.resolvedUrl("KeysPage.qml"))
            }
            MenuItem {
                visible: Gpg.smimeEnabled
                text: qsTr("S/MIME certificates")
                onClicked: pageStack.push(Qt.resolvedUrl("SmimeCertsPage.qml"))
            }
            MenuItem {
                text: qsTr("Sync all inboxes")
                onClicked: emailAgent.accountsSyncInbox()
            }
            // LAST → sits at the very bottom of the pulley (primary action, reached
            // with the smallest pull).
            MenuItem {
                text: qsTr("New message")
                onClicked: pageStack.push(Qt.resolvedUrl("ComposerPage.qml"))
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: qsTr("SF-Mail")
                description: emailAgent.synchronizing ? qsTr("Syncing…") : ""
            }

            BackgroundItem {
                width: parent.width
                visible: accountsModel.numberOfAccounts > 1
                onClicked: pageStack.push(Qt.resolvedUrl("MessageListPage.qml"),
                                          { folderAccessor: emailAgent.combinedInboxAccessor(),
                                            title: qsTr("Combined inbox") })
                Label {
                    x: Theme.horizontalPageMargin
                    anchors.verticalCenter: parent.verticalCenter
                    text: qsTr("Combined inbox")
                    color: highlighted ? Theme.highlightColor : Theme.primaryColor
                }
            }

            Repeater {
                model: accountsModel
                delegate: ListItem {
                    id: acctItem
                    width: page.width
                    contentHeight: Theme.itemSizeMedium
                    // The user's default sending account — shown bold + highlighted.
                    property bool isDefault: page._defaultTick >= 0
                                             && Gpg.defaultAccountId() === model.mailAccountId
                    onClicked: page.openInbox(model.mailAccountId,
                                              model.displayName !== "" ? model.displayName
                                                                       : model.emailAddress)
                    menu: ContextMenu {
                        MenuItem {
                            text: qsTr("Show folders")
                            onClicked: pageStack.push(Qt.resolvedUrl("FoldersPage.qml"),
                                                      { accountId: model.mailAccountId,
                                                        accountName: model.displayName !== "" ? model.displayName
                                                                                              : model.emailAddress })
                        }
                        MenuItem {
                            text: acctItem.isDefault ? qsTr("Remove as default sender")
                                                     : qsTr("Set as default sender")
                            onClicked: {
                                Gpg.setDefaultAccountId(acctItem.isDefault ? 0 : model.mailAccountId)
                                page._defaultTick++
                            }
                        }
                    }
                    Column {
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        Label {
                            width: parent.width
                            truncationMode: TruncationMode.Fade
                            text: (model.displayName !== "" ? model.displayName : model.emailAddress)
                                  + (acctItem.isDefault ? "  ★" : "")
                            font.weight: acctItem.isDefault ? Font.Bold : Font.Normal
                            color: acctItem.highlighted || acctItem.isDefault ? Theme.highlightColor
                                                                              : Theme.primaryColor
                        }
                        Label {
                            width: parent.width
                            truncationMode: TruncationMode.Fade
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryColor
                            text: model.emailAddress
                                  + (model.unreadCount > 0 ? "  •  " + model.unreadCount + " " + qsTr("unread") : "")
                        }
                    }
                }
            }

            ViewPlaceholder {
                enabled: accountsModel.numberOfAccounts === 0
                text: qsTr("No e-mail accounts")
                hintText: qsTr("Add an account in the system settings first")
            }
        }
        VerticalScrollDecorator { }
    }
}
