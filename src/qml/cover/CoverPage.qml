import QtQuick 2.6
import Sailfish.Silica 1.0

CoverBackground {
    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.paddingLarge
        spacing: Theme.paddingMedium

        Image {
            anchors.horizontalCenter: parent.horizontalCenter
            source: "image://theme/icon-cover-message"
        }
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: "SF-Mail"
            color: Theme.highlightColor
            font.pixelSize: Theme.fontSizeLarge
        }
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: qsTr("OpenPGP")
            color: Theme.secondaryColor
            font.pixelSize: Theme.fontSizeExtraSmall
        }
    }
}
