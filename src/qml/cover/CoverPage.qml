import QtQuick 2.6
import Sailfish.Silica 1.0

CoverBackground {
    // faint oversized app-icon watermark behind the cover content
    Image {
        anchors.centerIn: parent
        source: "/usr/share/icons/hicolor/172x172/apps/harbour-sfmail.png"
        sourceSize { width: 172; height: 172 }
        width: parent.width * 1.5
        height: width
        fillMode: Image.PreserveAspectFit
        opacity: 0.12
        smooth: true
        asynchronous: true
    }

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
