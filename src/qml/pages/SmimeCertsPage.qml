import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import SFMail.Gpg 1.0

// Stufe-1 test bench for the S/MIME (gpgsm) backend: import a .p12, list the
// resulting certs, run a round-trip self-test, decrypt a file. Deliberately bare —
// once the plugin is proven here it gets wired into harbour-sfmail proper.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations

    property string _log: ""
    property var _certs: []

    property var _certTree: []

    // Deferred certificate generation: set the params, show the notice, then run on
    // a short timer so the "Generating…" line paints before the (blocking) openssl
    // key-gen + gpgsm import. (generateCert reuses the synchronous importP12 path.)
    property string _genName: ""
    property string _genEmail: ""
    property string _genPass: ""
    Timer {
        id: _genTimer
        interval: 60
        onTriggered: Smime.generateCert(page._genName, page._genEmail, page._genPass)
    }

    function _appendLog(s) { page._log = s + "\n" + page._log }
    function _refresh() { page._certs = Smime.listCerts(); page._certTree = _organize(page._certs) }

    // Order the flat cert list into per-chain groups: each tree's leaf (user) certs
    // first, then its Intermediate CA, then its Root CA — so what belongs together
    // sits together and the CAs are indented under the user cert.
    function _organize(certs) {
        var byFpr = {}
        for (var i = 0; i < certs.length; ++i) byFpr[certs[i].fpr] = certs[i]
        function rootOf(c) {
            var cur = c, g = 0
            while (cur && !cur.isRoot && g < 16) { var nx = byFpr[cur.chainId]; if (!nx) break; cur = nx; ++g }
            return cur ? cur.fpr : (c.chainId || c.fpr)
        }
        var ann = []
        for (var j = 0; j < certs.length; ++j) {
            var c = certs[j]
            var leaf = !c.isCA
            var role = leaf ? (c.hasSecret ? "user" : "leaf") : (c.isRoot ? "root" : "intermediate")
            var indent = leaf ? 0 : (c.isRoot ? 2 : 1)
            ann.push({ c: c, role: role, indent: indent, root: rootOf(c) })
        }
        ann.sort(function(a, b) {
            if (a.root !== b.root) return a.root < b.root ? -1 : 1
            if (a.indent !== b.indent) return a.indent - b.indent
            var ua = a.c.uid || "", ub = b.c.uid || ""
            return ua < ub ? -1 : ua > ub ? 1 : 0
        })
        return ann
    }

    function _roleLabel(item) {
        if (item.role === "root") return qsTr("Root CA")
        if (item.role === "intermediate") return qsTr("Intermediate CA")
        var u = item.c.keyUsage || ""
        if (u.toLowerCase().indexOf("e") >= 0) return qsTr("Your encryption certificate")
        if (u.toLowerCase().indexOf("s") >= 0) return qsTr("Your signing certificate")
        return qsTr("Certificate")
    }

    Component.onCompleted: _refresh()

    Connections {
        target: Smime
        onLogLine: page._appendLog(line)
        onCertsChanged: page._refresh()
        onImportFinished: {
            page._appendLog(ok ? ("✓ import: " + imported + " key(s)")
                               : ("✗ import failed: " + error))
            if (ok && page._importSrcToDelete.length > 0) {
                var del = Gpg.shredFile(page._importSrcToDelete)
                page._appendLog(del ? qsTr("Import file deleted from the device.")
                                    : qsTr("Could not delete the import file."))
            }
            page._importSrcToDelete = ""
            _refresh()
        }
        onRoundTripFinished: page._appendLog(ok ? ("✓ round-trip OK: " + text.trim())
                                                : ("✗ round-trip failed: " + error))
        onDecryptFinished: page._appendLog(ok ? ("✓ decrypted:\n" + text)
                                              : ("✗ decrypt failed: " + error))
    }

    // A file picker is a separate page; we must pop back to THIS page before asking
    // the passphrase, so afterwards the result + cert list are visible (not the
    // file view). The picker stashes the action here and pops; onStatusChanged then
    // opens the passphrase dialog once this page is active again.
    property string _pendingAction: ""   // "import" | "decrypt"
    property string _pendingArg: ""
    property string _pendingInfo: ""
    property string _importSrcToDelete: ""   // import source to shred after success

    onStatusChanged: {
        if (status === PageStatus.Active && _pendingAction !== "") {
            var a = _pendingAction, arg = _pendingArg, info = _pendingInfo
            _pendingAction = ""; _pendingArg = ""; _pendingInfo = ""
            _runWithPassphrase(a, arg, info)
        }
    }

    // Push the passphrase dialog (this page is active) and run the action.
    function _runWithPassphrase(action, arg, info) {
        var dlg = pageStack.push(Qt.resolvedUrl("PassphraseDialog.qml"),
                                 { info: info, offerDeleteSource: (action === "import") })
        dlg.accepted.connect(function() {
            if (action === "import") {
                page._importSrcToDelete = (dlg.deleteSource ? arg : "")
                Smime.importP12(arg, dlg.passphrase, "")
            }
            else if (action === "decrypt")   Smime.decryptFile(arg, dlg.passphrase)
            else if (action === "roundtrip") Smime.roundTripTest(dlg.passphrase)
            else if (action === "exportp12") {
                var p = Smime.saveP12ToDocuments(arg, dlg.passphrase)
                page._appendLog(p.length > 0
                    ? (qsTr("Certificate backed up to %1").arg(p) + " "
                       + qsTr("It is passphrase-protected but lies outside the app sandbox — copy it off-device and then delete it from the phone."))
                    : qsTr("Backup failed — wrong passphrase?"))
            }
        })
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem { text: qsTr("Wipe store"); onClicked: Smime.wipeStore() }
            MenuItem { text: qsTr("Round-trip self-test")
                       enabled: Smime.available
                       onClicked: _runWithPassphrase("roundtrip", "", qsTr("Passphrase of your key")) }
            // One file-import for BOTH: your own identity cert (.p12/.pfx, with a
            // private key → asks the passphrase) and a public/CA certificate
            // (.pem/.crt/.p7b → imported directly). The type is detected from the
            // file. (A sender's cert FROM a received mail is imported in the mail
            // view, not here.)
            MenuItem { text: qsTr("Import certificate from file…")
                       enabled: Smime.available
                       onClicked: pageStack.push(certPicker) }
            MenuItem {
                text: qsTr("Generate new certificate…")
                enabled: Smime.available
                onClicked: {
                    var dlg = pageStack.push(Qt.resolvedUrl("GenerateIdentityDialog.qml"), {
                        heading: qsTr("Generate S/MIME certificate"),
                        intro: qsTr("Creates a new self-signed RSA-4096 S/MIME certificate (signing + encryption) in your store. The recipient must trust it once, like a first key exchange. Highest security; the passphrase is mandatory."),
                        commandText:
                            "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \\\n" +
                            "    -days 730 -nodes -sha256 \\\n" +
                            "    -subj \"/CN=Max Mustermann/emailAddress=max@example.org\" \\\n" +
                            "    -addext \"basicConstraints=critical,CA:FALSE\" \\\n" +
                            "    -addext \"keyUsage=critical,digitalSignature,keyEncipherment\" \\\n" +
                            "    -addext \"extendedKeyUsage=emailProtection\" \\\n" +
                            "    -addext \"subjectAltName=email:max@example.org\"\n" +
                            "openssl pkcs12 -export -inkey key.pem -in cert.pem -out identity.p12\n" +
                            "gpgsm --import identity.p12   (+ trustlist entry for the self-signed root)"
                    })
                    dlg.accepted.connect(function() {
                        page._genName = dlg.genName
                        page._genEmail = dlg.genEmail
                        page._genPass = dlg.genPass
                        page._appendLog(qsTr("Generating a 4096-bit certificate — this can take a minute…"))
                        _genTimer.start()
                    })
                }
            }
        }

        Column {
            id: col
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader { title: qsTr("S/MIME certificates") }

            Item { width: 1; height: Theme.paddingSmall }

            DetailItem { label: qsTr("gpgsm"); value: Smime.available ? qsTr("ready") : qsTr("NOT FOUND") }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WrapAnywhere
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("store: ") + Smime.gnupgHome
            }

            SectionHeader { text: qsTr("Certificates (%1)").arg(page._certs.length) }
            Repeater {
                model: page._certTree
                delegate: ListItem {
                    id: certItem
                    width: page.width
                    contentHeight: cc.height + Theme.paddingMedium
                    property bool _isCA: modelData.role === "root" || modelData.role === "intermediate"
                    // Tap → details + PEM (KeyTextPage has "Copy to clipboard" = export),
                    // same as PGP "Show / export public key".
                    onClicked: pageStack.push(Qt.resolvedUrl("KeyTextPage.qml"), {
                        title: _roleLabel(modelData),
                        text: _roleLabel(modelData)
                              + "\n" + (modelData.c.uid && modelData.c.uid !== "" ? modelData.c.uid : qsTr("(no subject)"))
                              + "\n\nFingerprint:\n" + (modelData.c.fpr || "")
                              + "\nKey usage: " + (modelData.c.keyUsage || "")
                              + (modelData.c.hasSecret ? "\nPrivate key: yes" : "")
                              + "\n\n" + Smime.exportCert(modelData.c.fpr || "")
                    })
                    menu: ContextMenu {
                        MenuItem {
                            text: qsTr("Show / export certificate")
                            onClicked: pageStack.push(Qt.resolvedUrl("KeyTextPage.qml"), {
                                title: _roleLabel(modelData),
                                text: Smime.exportCert(modelData.c.fpr || "")
                            })
                        }
                        MenuItem {
                            visible: modelData.c.hasSecret === true
                            text: qsTr("Back up as .p12 to Documents…")
                            onClicked: _runWithPassphrase("exportp12", modelData.c.fpr || "",
                                                          qsTr("Passphrase of this certificate"))
                        }
                        MenuItem {
                            text: modelData.c.hasSecret ? qsTr("Delete certificate + private key")
                                                        : qsTr("Delete certificate")
                            onClicked: {
                                var fpr = modelData.c.fpr || "", sec = modelData.c.hasSecret === true
                                var dlg = pageStack.push(Qt.resolvedUrl("ConfirmDialog.qml"), {
                                    question: qsTr("Really delete this certificate?"),
                                    warning: sec ? qsTr("This includes the PRIVATE key. Without a .p12 backup it cannot be recovered.")
                                                 : qsTr("The certificate will be removed from your store."),
                                    acceptText: qsTr("Delete")
                                })
                                dlg.accepted.connect(function() {
                                    certItem.remorseAction(qsTr("Deleting certificate"),
                                                           function() { Smime.deleteCert(fpr) })
                                })
                            }
                        }
                    }
                    Column {
                        id: cc
                        // Indent CAs to the right so they sit visually under the user
                        // cert they belong to.
                        x: Theme.horizontalPageMargin + modelData.indent * Theme.itemSizeExtraSmall
                        width: page.width - x - Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        Label {
                            width: parent.width; truncationMode: TruncationMode.Fade
                            text: (_isCA ? "↳ " : "") + _roleLabel(modelData)
                                  + (modelData.c.hasSecret ? "   🔑" : "")
                            font.pixelSize: Theme.fontSizeSmall
                            color: _isCA ? Theme.secondaryColor
                                 : (modelData.c.hasSecret ? Theme.highlightColor : Theme.primaryColor)
                        }
                        Label {
                            width: parent.width; truncationMode: TruncationMode.Fade
                            text: modelData.c.uid && modelData.c.uid !== "" ? modelData.c.uid : qsTr("(no subject)")
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryColor
                        }
                        Label {
                            width: parent.width; truncationMode: TruncationMode.Fade
                            text: (modelData.c.fpr || "")
                            font.pixelSize: Theme.fontSizeTiny
                            color: Theme.secondaryHighlightColor
                        }
                    }
                }
            }

            SectionHeader { text: qsTr("Log") }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                font.family: "monospace"
                text: page._log
            }
        }
        VerticalScrollDecorator { }
    }

    Component {
        id: certPicker
        FilePickerPage {
            allowedOrientations: defaultAllowedOrientations
            title: qsTr("Select certificate (.p12 / .pfx / .pem / .crt / .p7b)")
            onSelectedContentPropertiesChanged: {
                var f = "" + selectedContentProperties.filePath
                if (/\.(p12|pfx)$/i.test(f)) {
                    // Own identity cert (private key) → ask the passphrase back on the
                    // cert page (onStatusChanged), so the result is visible afterwards.
                    page._pendingArg = f
                    page._pendingInfo = qsTr("Passphrase of the .p12 file")
                    page._pendingAction = "import"
                    pageStack.pop(page)
                } else {
                    // Public certificate / CA → import directly, no passphrase.
                    Smime.importCertFromFile(f)
                    pageStack.pop(page)
                }
            }
        }
    }
}
