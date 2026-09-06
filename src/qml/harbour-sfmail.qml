import QtQuick 2.6
import Sailfish.Silica 1.0
import "pages"

ApplicationWindow {
    id: app
    visible: true
    cover: Qt.resolvedUrl("cover/CoverPage.qml")
    allowedOrientations: defaultAllowedOrientations
    // Make pages that don't set allowedOrientations themselves follow the device
    // too — notably the Sailfish.Pickers internals (DirectoryPage), which otherwise
    // default to Portrait and so appear rotated 90° (and stall) on landscape
    // devices. Our own pages all set it explicitly, so this only
    // affects such third-party/internal pages. (We don't patch system QML files.)
    _defaultPageOrientations: defaultAllowedOrientations
    // Silica labels default to Text.AutoText, which turns anything that looks
    // like markup into rich text — and a rich-text Label FETCHES <img src=http…>.
    // Subject lines, sender names, certificate subjects and key user ids are all
    // written by strangers, so a crafted subject would phone home the moment the
    // message list draws it. Plain text everywhere; the one deliberate HTML view
    // (the message body) sets its own textFormat.
    _defaultLabelFormat: Text.PlainText
    initialPage: Component { MailAccountsPage { } }
}
