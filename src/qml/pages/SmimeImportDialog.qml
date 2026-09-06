import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// Confirm an S/MIME certificate import. The certificates were already read by
// the plugin (Smime.inspectCertImport) and stashed; this dialog shows WHAT they
// are before anything enters the store — subject, addresses, issuer, validity
// and the full fingerprint, plus the warnings that matter: the certificate does
// not carry the sender's address, a DIFFERENT certificate is already stored for
// that address, or the certificate has expired.
//
// Accepting imports the stashed batch via Smime.importInspected(). A root
// certificate becomes a TRUST ANCHOR only if the user ticks that switch: from
// then on everything that CA signs counts as valid, which is exactly the
// decision no program may take on the user's behalf.
Dialog {
    id: dialog
    allowedOrientations: defaultAllowedOrientations

    // The QVariantMap from Smime.inspectCertImport().
    property var info: ({})
    // Shown above the list, e.g. "This certificate came with a signed message."
    property string intro: ""

    readonly property var _certs: (info && info.certs) ? info.certs : []
    readonly property bool _senderKnown: info.senderKnown === true
    readonly property bool _senderMatches: info.senderMatches === true
    readonly property bool _senderMismatch: _senderKnown && !_senderMatches
    readonly property bool _hasRoot: info.hasRoot === true
    readonly property bool _rootsTrusted: info.rootsTrusted === true
    readonly property bool _anyConflict: {
        for (var i = 0; i < _certs.length; ++i)
            if (_certs[i].conflicts && _certs[i].conflicts.length > 0) return true
        return false
    }
    readonly property bool _anyExpired: {
        for (var i = 0; i < _certs.length; ++i)
            if (_certs[i].expired === true) return true
        return false
    }
    // Offer the anchor switch only for a root that is not an anchor already.
    readonly property bool _offerTrust: _hasRoot && !_rootsTrusted

    property bool trustRoots: false
    property bool fetchChain: false

    function _grouped(fpr) {
        var s = ("" + fpr).toUpperCase().replace(/\s/g, "")
        var out = ""
        for (var i = 0; i < s.length; i += 4)
            out += (i > 0 ? " " : "") + s.substr(i, 4)
        return out
    }

    onAccepted: Smime.importInspected(dialog.trustRoots, dialog.fetchChain)

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height

        Column {
            id: col
            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader {
                acceptText: (dialog._senderMismatch || dialog._anyConflict || dialog._anyExpired)
                            ? qsTr("Import anyway") : qsTr("Import")
                cancelText: qsTr("Cancel")
                title: dialog._certs.length > 1 ? qsTr("Import %1 certificates?").arg(dialog._certs.length)
                                                : qsTr("Import certificate?")
            }

            Label {
                visible: dialog.intro !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: dialog.intro
            }

            // --- does this belong to the SENDER? (the check that matters most) ---
            Label {
                visible: dialog._senderMismatch
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#ff5050"
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("⚠ None of these certificates is issued for the sender's address (%1). Only import them if you are sure they really belong to this sender.")
                      .arg(info.senderEmail ? info.senderEmail : "?")
            }
            Label {
                visible: dialog._senderKnown && dialog._senderMatches
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: "#60c060"
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("✓ Issued for the sender's address (%1).").arg(info.senderEmail)
            }

            // --- one block per certificate ---------------------------------
            Repeater {
                model: dialog._certs
                delegate: Column {
                    x: Theme.horizontalPageMargin
                    width: dialog.width - 2 * Theme.horizontalPageMargin
                    spacing: 2

                    SectionHeader {
                        text: modelData.isCA ? (modelData.selfSigned ? qsTr("Root certificate authority")
                                                                     : qsTr("Certificate authority"))
                                             : qsTr("Certificate")
                    }
                    Label {
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeMedium
                        color: Theme.highlightColor
                        text: modelData.subject ? modelData.subject : qsTr("(no subject)")
                    }
                    Label {
                        visible: modelData.emails && modelData.emails.length > 0
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeSmall
                        text: ("" + (modelData.emails ? modelData.emails.join(", ") : ""))
                    }
                    Label {
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        text: qsTr("issued by: ") + (modelData.issuer ? modelData.issuer : "?")
                    }
                    Label {
                        width: parent.width; wrapMode: Text.WrapAnywhere
                        font.pixelSize: Theme.fontSizeExtraSmall
                        font.family: "monospace"
                        color: Theme.highlightColor
                        text: dialog._grouped(modelData.fpr)
                    }
                    Label {
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: modelData.expired ? "#ffa030" : Theme.secondaryColor
                        text: modelData.expired
                              ? qsTr("EXPIRED on %1").arg(modelData.notAfter ? modelData.notAfter : "?")
                              : qsTr("valid until %1").arg(modelData.notAfter ? modelData.notAfter : "?")
                    }
                    Label {
                        visible: modelData.inStore === true
                        width: parent.width; wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        text: qsTr("Already in your store — importing changes nothing.")
                    }
                    // A different certificate is already stored for the same address.
                    Repeater {
                        model: modelData.conflicts ? modelData.conflicts : []
                        delegate: Label {
                            width: dialog.width - 2 * Theme.horizontalPageMargin
                            wrapMode: Text.WordWrap
                            font.pixelSize: Theme.fontSizeSmall
                            color: "#ffa030"
                            text: qsTr("⚠ You already have a DIFFERENT certificate for this address: %1. Importing adds a second one; the newest usable certificate is used when encrypting.")
                                  .arg(modelData.subject ? modelData.subject : modelData.fpr)
                        }
                    }
                    Item { width: 1; height: Theme.paddingSmall }
                }
            }

            // --- trust decision --------------------------------------------
            SectionHeader { visible: dialog._offerTrust; text: qsTr("Trust") }
            TextSwitch {
                visible: dialog._offerTrust
                checked: dialog.trustRoots
                onCheckedChanged: dialog.trustRoots = checked
                text: qsTr("Trust this root certificate")
                description: qsTr("Signatures from every certificate this authority issues will count as valid, now and in future. Turn this on only for an authority you know — for example your own certificate, or your organisation's.")
            }
            Label {
                visible: dialog._hasRoot && dialog._rootsTrusted
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("This root is already one of your trust anchors.")
            }

            TextSwitch {
                checked: dialog.fetchChain
                onCheckedChanged: dialog.fetchChain = checked
                text: qsTr("Fetch missing issuer certificates")
                description: qsTr("Downloads the issuing authorities named inside the certificate, over an encrypted connection. This tells that server that you received this mail. Nothing downloaded becomes trusted.")
            }

            Item { width: 1; height: Theme.paddingLarge }
        }
        VerticalScrollDecorator { }
    }
}
