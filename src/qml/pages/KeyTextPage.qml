import QtQuick 2.6
import Sailfish.Silica 1.0

// Read-only Anzeige eines Text-/ASCII-Armor-Blocks (z. B. exportierter Key,
// E-Mail-Header) mit Kopier-Funktion. Der Text wird ZEILENWEISE als einzelne
// kleine Labels gerendert (nicht als ein großes Text-Element) — ein einzelnes
// großes Text-Element blockiert auf manchen Geräten den Scene-Graph-Render-
// Thread (per gdb belegt: QSGRenderThread hängt in WaylandNativeWindow::
// queueBuffer/sync_wait). Viele kleine Labels (wie in CryptoInfoPage) sind ok.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property string title: ""
    property string text: ""

    readonly property var _lines: text.length > 0 ? text.split("\n") : []

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                text: qsTr("Copy to clipboard")
                onClicked: Clipboard.text = page.text
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingSmall

            PageHeader { title: page.title }

            Repeater {
                model: page._lines
                delegate: Label {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    text: modelData
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.highlightColor
                }
            }
        }
        VerticalScrollDecorator { }
    }
}
