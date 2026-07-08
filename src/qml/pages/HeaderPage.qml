import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// Vollständige Roh-Header einer Nachricht + Absender-Auswertung (SPF/DKIM/DMARC,
// From↔Return-Path-Abgleich, Absender-IP) + optionaler Blacklist-Check (nur
// Absender-IP/Domain). Liest die Header direkt aus der QMF-Content-Datei
// (kein QMailMessage → kein Freeze).
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property int messageId: 0
    property var info: ({})
    property string _blStatus: ""
    // Active (DNS) SPF/DMARC results.
    property string _spf: "checking…"
    property string _spfInfo: ""
    property string _dmarc: "checking…"
    property string _dmarcInfo: ""

    readonly property var _lines: (info && info.rawText && info.rawText.length > 0)
                                  ? info.rawText.split("\n") : []

    ListModel { id: blModel }

    Component.onCompleted: {
        page.info = Gpg.analyzeSender(page.messageId)
        // Verify SPF + DMARC ourselves via DNS (independent of the server header).
        Gpg.checkAuth(("" + (info.fromDomain || "")), ("" + (info.returnPathDomain || "")),
                      ("" + (info.originIp || "")), ("" + (info.dkimDomain || "")))
    }

    Connections {
        target: Gpg
        onBlacklistResult: blModel.append({ bname: name, bstatus: status, bdetail: detail })
        onBlacklistDone: {
            var listed = 0
            for (var i = 0; i < blModel.count; ++i)
                if (blModel.get(i).bstatus === "listed") listed++
            page._blStatus = listed > 0 ? qsTr("⚠ listed on %1 list(s)!").arg(listed)
                                        : qsTr("Done — not listed.")
        }
        onSpfResult: { page._spf = result; page._spfInfo = info }
        onDmarcResult: { page._dmarc = verdict + " (" + policy + ")"; page._dmarcInfo = info }
    }

    function _authColor(v) {
        var s = ("" + v).toLowerCase()
        if (s === "pass") return "#4caf50"
        if (s === "" || s === "none" || s === "neutral") return Theme.secondaryColor
        return "#ff4d4d"   // fail / softfail / permerror …
    }
    function _runBlacklists() {
        blModel.clear()
        page._blStatus = qsTr("Checking…")
        Gpg.checkBlacklists(("" + (info.originIp || "")), ("" + (info.fromDomain || "")),
                            (info.linkDomains ? info.linkDomains : []))
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                text: qsTr("Check sender against blacklists")
                onClicked: page._runBlacklists()
            }
            MenuItem {
                text: qsTr("Copy headers")
                onClicked: Clipboard.text = (info.rawText || "")
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingSmall

            PageHeader { title: qsTr("Header & sender check") }

            SectionHeader { text: qsTr("Sender analysis") }

            DetailItem { label: qsTr("From"); value: info.from ? info.from : "—" }
            DetailItem {
                label: qsTr("Return-Path")
                value: info.returnPath ? info.returnPath : "—"
            }
            // From vs Return-Path mismatch (spoofing hint)
            Label {
                visible: info.mismatch === true
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: "#ff4d4d"
                text: qsTr("⚠ From domain (%1) ≠ Return-Path domain (%2) — possible spoofing.")
                      .arg(info.fromDomain || "?").arg(info.returnPathDomain || "?")
            }

            // SPF / DMARC — actively verified by us via DNS.
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                text: "SPF: " + page._spf
                color: page._authColor(page._spf)
            }
            Label {
                visible: page._spfInfo !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Qt.rgba(1,1,1,0.35)
                text: page._spfInfo
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                text: "DMARC: " + page._dmarc
                color: page._dmarc.indexOf("pass") === 0 ? "#4caf50"
                       : page._dmarc.indexOf("fail") === 0 ? "#ff4d4d" : Theme.secondaryColor
            }
            Label {
                visible: page._dmarcInfo !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Qt.rgba(1,1,1,0.35)
                text: page._dmarcInfo
            }
            // DKIM — only the header verdict (if any); NOT cryptographically
            // verified here. Kept low-key (semi-transparent grey).
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Qt.rgba(1,1,1,0.35)
                text: "DKIM: " + (info.dkim ? info.dkim + " (per receiving server)"
                                : info.dkimDomain ? qsTr("signature present (d=%1) — not cryptographically verified here").arg(info.dkimDomain)
                                : qsTr("no DKIM signature"))
            }

            DetailItem {
                label: qsTr("Sender IP")
                value: (info.originIp ? info.originIp : "—")
                       + (info.originHost ? "  (" + info.originHost + ")" : "")
            }

            // Links found in the message body (their domains get DNSBL-checked too).
            SectionHeader {
                visible: info.linkDomains && info.linkDomains.length > 0
                text: qsTr("Link domains (%1)").arg(info.linkDomains ? info.linkDomains.length : 0)
            }
            Repeater {
                model: info.linkDomains ? info.linkDomains : []
                delegate: Label {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: modelData
                }
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                wrapMode: Text.WordWrap
                text: qsTr("Pull down to check the sender's IP/domain — and any link domains — "
                           + "against blacklists. Only those values are sent to the blacklist DNS, "
                           + "nothing of yours.")
            }

            // --- Blacklist results -----------------------------------------
            SectionHeader { visible: blModel.count > 0 || page._blStatus !== ""; text: qsTr("Blacklists") }
            Label {
                visible: page._blStatus !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                font.pixelSize: Theme.fontSizeSmall
                text: page._blStatus
                color: page._blStatus.indexOf("⚠") >= 0 ? "#ff4d4d" : Theme.highlightColor
            }
            Repeater {
                model: blModel
                delegate: Item {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    height: bl.height
                    Label {
                        id: bl
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.pixelSize: Theme.fontSizeExtraSmall
                        text: model.bname + ": " + model.bstatus
                              + (model.bdetail ? "  (" + model.bdetail + ")" : "")
                        color: model.bstatus === "listed" ? "#ff4d4d"
                               : model.bstatus === "clean" ? "#4caf50" : Theme.secondaryColor
                    }
                }
            }

            // --- Full raw headers ------------------------------------------
            SectionHeader { text: qsTr("Raw headers") }
            Repeater {
                model: page._lines
                delegate: Label {
                    x: Theme.horizontalPageMargin
                    width: page.width - 2 * Theme.horizontalPageMargin
                    text: modelData
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                }
            }
        }
        VerticalScrollDecorator { }
    }
}
