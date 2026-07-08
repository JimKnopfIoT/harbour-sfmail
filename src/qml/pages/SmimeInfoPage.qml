import QtQuick 2.6
import Sailfish.Silica 1.0

// S/MIME encryption/certificate info for one message. Shows the recipient
// (encryption) certificates the mail is encrypted to — yours AND the other
// party's — each with its CA chain up to the root, the signature certificates
// embedded in the message, plus a raw debug dump. For unencrypted mail it just
// says "No encryption". info = Map from Smime.messageCertInfo().
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property var info: ({})
    property string title: qsTr("Encryption info")
    property bool _showDebug: false

    readonly property bool _unenc: info && info.unencrypted === true
    readonly property var _recips: (info && info.encRecipients) ? info.encRecipients : []
    readonly property var _signs:  (info && info.signCerts) ? info.signCerts : []

    function _roleOf(r) {
        if (r.hasSecret) return qsTr("You (your certificate — decryptable)")
        if (!r.inStore)  return qsTr("Recipient (cert not in your store)")
        return qsTr("Other recipient")
    }
    function _color(r) {
        if (r.hasSecret) return "#4caf50"
        if (!r.inStore)  return Theme.secondaryColor
        return Theme.primaryColor
    }
    function _asText() {
        var t = "Format: " + (info.format || "?") + "\n\n== Encryption recipients ==\n"
        for (var i = 0; i < _recips.length; ++i) {
            var r = _recips[i]
            t += "\n" + _roleOf(r) + "\n  " + (r.subject || "") + "\n  " + (r.algo || "") + "  " + (r.fpr || "") + "\n"
            var ch = r.chain || []
            for (var j = 0; j < ch.length; ++j) t += "    ↳ " + ch[j].role + ": " + ch[j].subject + "  (" + ch[j].fpr + ")\n"
        }
        t += "\n== Signature certificates ==\n"
        for (var k = 0; k < _signs.length; ++k)
            t += "\n  subject: " + (_signs[k].subject || "") + "\n  issuer:  " + (_signs[k].issuer || "") + "\n"
        t += "\n== Debug ==\n" + (info.debug || "")
        return t
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                visible: !!info.debug
                text: page._showDebug ? qsTr("Hide debug info") : qsTr("Show debug info")
                onClicked: page._showDebug = !page._showDebug
            }
            MenuItem { text: qsTr("Copy all to clipboard"); onClicked: Clipboard.text = page._asText() }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader { title: page.title }

            DetailItem { label: qsTr("Format"); value: page._unenc ? qsTr("No encryption") : (info.format || "—") }

            Label {
                visible: info.error && info.error.length > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#ff4d4d"
                font.pixelSize: Theme.fontSizeSmall
                text: info.error || ""
            }

            // Unencrypted note
            Label {
                visible: page._unenc
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: Theme.secondaryColor
                text: qsTr("This message is not encrypted.")
            }

            // ---- Encryption recipients ----
            SectionHeader {
                visible: page._recips.length > 0
                text: qsTr("Encrypted to %1 certificate(s)").arg(page._recips.length)
            }
            Repeater {
                model: page._recips
                delegate: Column {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    spacing: 2
                    Label {
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeMedium
                        color: page._color(modelData)
                        text: page._roleOf(modelData)
                    }
                    Label {
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: modelData.subject || qsTr("(no subject)")
                    }
                    Label {
                        visible: !!modelData.fpr
                        width: parent.width; wrapMode: Text.WrapAnywhere
                        font.pixelSize: Theme.fontSizeExtraSmall; font.family: "monospace"
                        color: Theme.highlightColor
                        text: (modelData.algo ? modelData.algo + "  " : "") + (modelData.fpr || "")
                    }
                    Label {
                        visible: !!modelData.keyUsage
                        font.pixelSize: Theme.fontSizeExtraSmall; color: Theme.secondaryColor
                        text: qsTr("Key usage: ") + (modelData.keyUsage || "")
                    }
                    // CA chain up to root
                    Repeater {
                        model: modelData.chain || []
                        delegate: Label {
                            x: Theme.paddingLarge
                            width: page.width - 2 * Theme.horizontalPageMargin - Theme.paddingLarge
                            wrapMode: Text.WordWrap
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryColor
                            text: "↳ " + modelData.role + ": " + (modelData.subject || "")
                        }
                    }
                    Item { width: 1; height: Theme.paddingSmall }
                }
            }

            // ---- Signature certificates ----
            SectionHeader {
                visible: page._signs.length > 0
                text: qsTr("Signature certificate(s): %1").arg(page._signs.length)
            }
            Repeater {
                model: page._signs
                delegate: Column {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    spacing: 2
                    Label {
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: modelData.subject || qsTr("(no subject)")
                    }
                    Label {
                        visible: !!modelData.issuer
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeExtraSmall; color: Theme.secondaryColor
                        text: qsTr("issued by: ") + (modelData.issuer || "")
                    }
                    Item { width: 1; height: Theme.paddingSmall }
                }
            }
            Label {
                visible: !!info.signNote
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall; color: Theme.secondaryColor
                text: info.signNote || ""
            }

            // ---- Debug dump (hidden by default; via pulley "Show debug info") ----
            SectionHeader { visible: page._showDebug && !!info.debug; text: qsTr("Debug") }
            Label {
                visible: page._showDebug && !!info.debug
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WrapAnywhere
                font.pixelSize: Theme.fontSizeTiny; font.family: "monospace"
                color: Theme.secondaryColor
                text: info.debug || ""
            }
        }
        VerticalScrollDecorator { }
    }
}
