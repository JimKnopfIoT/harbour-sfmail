import QtQuick 2.6
import Sailfish.Silica 1.0

// Shared "create a new identity" dialog for BOTH PGP key and S/MIME certificate
// generation. Enforces a strong passphrase (≥12 chars, upper- AND lower-case
// letters, a digit and a special character) and a valid e-mail address. On accept
// it exposes genName / genEmail / genPass; the pushing page reads those in its
// own accepted handler (PGP → Gpg.generateKey, S/MIME → Smime.generateCert).
Dialog {
    id: gd
    allowedOrientations: defaultAllowedOrientations

    // caller-supplied texts
    property string heading: qsTr("Generate new key")
    property string intro: ""
    // The actual command(s) used to generate the key — shown (with dummy data)
    // below the form so the user sees exactly what happens. Set by the caller.
    property string commandText: ""

    // results the caller reads in onAccepted
    readonly property string genName: nameField.text.trim()
    readonly property string genEmail: emailField.text.trim()
    readonly property string genPass: passField.text

    function _hasLower(p)   { return (/[a-z]/).test(p) }
    function _hasUpper(p)   { return (/[A-Z]/).test(p) }
    function _hasDigit(p)   { return (/[0-9]/).test(p) }
    function _hasSpecial(p) { return (/[^A-Za-z0-9]/).test(p) }
    function _pwStrong(p) {
        return p.length >= 12 && _hasLower(p) && _hasUpper(p)
               && _hasDigit(p) && _hasSpecial(p)
    }

    property string _pw: passField.text
    property bool _mailOk: (/^[^@\s]+@[^@\s]+\.[^@\s]+$/).test(emailField.text.trim())
    property bool _pwOk: _pwStrong(_pw)
    property bool _pwMatch: _pw.length > 0 && _pw === pass2Field.text

    canAccept: _mailOk && _pwOk && _pwMatch

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        Column {
            id: col
            width: parent.width
            spacing: Theme.paddingSmall

            DialogHeader { acceptText: qsTr("Generate") }

            Label {
                visible: gd.intro.length > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: gd.intro
            }

            TextField {
                id: nameField
                width: parent.width
                label: qsTr("Name")
                placeholderText: qsTr("Your name (optional)")
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: emailField.focus = true
            }
            TextField {
                id: emailField
                width: parent.width
                label: qsTr("E-mail address")
                placeholderText: qsTr("you@example.org")
                inputMethodHints: Qt.ImhEmailCharactersOnly | Qt.ImhNoAutoUppercase
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: passField.focus = true
                color: gd._mailOk || text.length === 0 ? Theme.primaryColor : "#ff6b6b"
            }
            TextField {
                id: passField
                width: parent.width
                label: qsTr("Passphrase")
                echoMode: TextInput.Password
                placeholderText: qsTr("At least 12 characters")
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: pass2Field.focus = true
            }
            TextField {
                id: pass2Field
                width: parent.width
                label: qsTr("Repeat passphrase")
                echoMode: TextInput.Password
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: if (gd.canAccept) gd.accept()
                color: gd._pwMatch || text.length === 0 ? Theme.primaryColor : "#ff6b6b"
            }

            // live requirement checklist
            Column {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                spacing: 0
                Label {
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: gd._pw.length >= 12 ? "#8bc34a" : Theme.secondaryColor
                    text: (gd._pw.length >= 12 ? "✓ " : "• ") + qsTr("at least 12 characters")
                }
                Label {
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: gd._hasUpper(gd._pw) && gd._hasLower(gd._pw) ? "#8bc34a" : Theme.secondaryColor
                    text: (gd._hasUpper(gd._pw) && gd._hasLower(gd._pw) ? "✓ " : "• ") + qsTr("upper- and lower-case letters")
                }
                Label {
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: gd._hasDigit(gd._pw) ? "#8bc34a" : Theme.secondaryColor
                    text: (gd._hasDigit(gd._pw) ? "✓ " : "• ") + qsTr("a digit")
                }
                Label {
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: gd._hasSpecial(gd._pw) ? "#8bc34a" : Theme.secondaryColor
                    text: (gd._hasSpecial(gd._pw) ? "✓ " : "• ") + qsTr("a special character")
                }
                Label {
                    visible: pass2Field.text.length > 0
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: gd._pwMatch ? "#8bc34a" : "#ff6b6b"
                    text: (gd._pwMatch ? "✓ " : "✗ ") + qsTr("passphrases match")
                }
            }

            // What actually runs — shown with dummy data for transparency.
            SectionHeader {
                visible: gd.commandText.length > 0
                text: qsTr("Command used (example data)")
            }
            Label {
                visible: gd.commandText.length > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WrapAnywhere
                textFormat: Text.PlainText
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: gd.commandText
            }
        }
    }
}
