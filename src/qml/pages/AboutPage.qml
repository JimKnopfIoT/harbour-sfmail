import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// App-Info: zeigt vor allem die laufende Version (kommt aus der Spec via
// SFMAIL_VERSION → Gpg.appVersion), damit man sofort sieht, welcher Build aktiv ist.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader { title: qsTr("About SF-Mail") }

            Image {
                anchors.horizontalCenter: parent.horizontalCenter
                source: "image://theme/icon-launcher-default"
                width: Theme.iconSizeLauncher
                height: width
                fillMode: Image.PreserveAspectFit
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                text: qsTr("SF-Mail")
                font.pixelSize: Theme.fontSizeLarge
                color: Theme.highlightColor
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                text: qsTr("Secure Friendly Mail")
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                text: qsTr("Version %1").arg(Gpg.appVersion)
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.primaryColor
            }

            Item { width: 1; height: Theme.paddingLarge }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: qsTr("Making e-mail encryption easy and friendly on Sailfish OS. "
                           + "Reads, writes, encrypts, decrypts and signs mail with built-in OpenPGP "
                           + "(PGP/MIME and inline) — and, when enabled, S/MIME (PKI / X.509) — using a "
                           + "bundled modern GnuPG with its own keyring.")
            }

            SectionHeader { text: qsTr("Features"); visible: Smime.available }
            // PGP is always on (the app's core). S/MIME is opt-in — keeps the app
            // slim for PGP-only users; turning it on reveals the S/MIME menus.
            // Hidden where S/MIME can't run (e.g. armv7 without bundled openssl).
            TextSwitch {
                visible: Smime.available
                text: qsTr("Enable S/MIME (PKI / X.509)")
                description: qsTr("Adds certificate management and S/MIME decrypt / import in the mail view. Off keeps the app PGP-only and slim.")
                automaticCheck: false
                checked: Gpg.smimeEnabled
                onClicked: Gpg.smimeEnabled = !Gpg.smimeEnabled
            }

            DetailItem {
                label: qsTr("OpenPGP backend")
                value: Gpg.available ? qsTr("ready") : qsTr("unavailable")
            }
            DetailItem {
                label: qsTr("Keyring")
                value: Gpg.gnupgHome
            }

            SectionHeader { text: qsTr("Diagnostics") }
            TextSwitch {
                text: qsTr("Debug logging")
                description: qsTr("Write a debug.log in the app's data folder to help diagnose problems. "
                                  + "Turn it off for normal use; it has no effect on your mail or keys.")
                automaticCheck: false
                checked: DebugLog.enabled
                onClicked: DebugLog.enabled = !DebugLog.enabled
            }
        }
        VerticalScrollDecorator { }
    }
}
