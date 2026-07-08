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
    initialPage: Component { MailAccountsPage { } }
}
