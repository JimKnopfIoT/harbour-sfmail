import QtQuick 2.6
import Sailfish.Silica 1.0
import SFMail.Gpg 1.0

// Wird beim verschlüsselten Versand gezeigt, wenn für einen Empfänger MEHRERE
// Keys existieren oder der gefundene Key revoked/abgelaufen ist. Pro Empfänger:
// Adresse editierbar (löst Keys neu auf) + Key-Auswahl, revoked/expired in ROT.
Dialog {
    id: dialog
    allowedOrientations: defaultAllowedOrientations

    property var recipients: []          // [{address, keys:[...]}]
    property var chosenAddresses: []
    property var chosenFingerprints: []

    // Working state (kept in plain JS arrays, refreshed via _tick).
    property var _addr: []
    property var _cand: []                // _cand[i] = [keyMap, …]
    property var _sel: []                 // selected fingerprint per recipient
    property int _tick: 0

    // Only a key that could actually be encrypted to may be selected at all —
    // same rule as the composer's _usableKeys().
    function _selectable(k) {
        return !k.revoked && !k.expired && k.canEncrypt
    }

    // Pre-select ONLY when the choice is unambiguous (exactly one usable key —
    // that recipient is not why this dialog is up). An ambiguous recipient
    // starts unselected: picking the key must be a conscious act, not a
    // confirmation of whatever happened to be first.
    function _preselect(keys) {
        var u = keys.filter(_selectable)
        return u.length === 1 ? ("" + u[0].fingerprint) : ""
    }

    Component.onCompleted: {
        var a = [], c = [], s = []
        for (var i = 0; i < recipients.length; ++i) {
            var keys = recipients[i].keys || []
            a.push("" + recipients[i].address)
            c.push(keys)
            s.push(_preselect(keys))
        }
        _addr = a; _cand = c; _sel = s; _tick++
    }

    function _reresolve(i, addr) {
        var keys = Gpg.publicKeys(addr)
        _addr[i] = addr
        _cand[i] = keys
        _sel[i] = _preselect(keys)
        _tick++
    }

    function _statusColor(k) {
        return _selectable(k) ? "#4caf50" : "#ff4d4d"
    }

    canAccept: {
        _tick   // dependency
        if (_sel.length === 0) return false
        for (var i = 0; i < _sel.length; ++i) if (!_sel[i]) return false
        return true
    }

    onAccepted: {
        chosenAddresses = _addr.slice()
        chosenFingerprints = _sel.slice()
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        Column {
            id: col
            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader { title: qsTr("Choose recipient keys"); acceptText: qsTr("Use selected") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeSmall
                color: "#ff4d4d"
                text: qsTr("More than one key — or a revoked/expired key — was found for a recipient. Check the address and pick the right key.")
            }

            Repeater {
                model: dialog.recipients.length
                delegate: Column {
                    id: recCol
                    width: col.width
                    spacing: Theme.paddingSmall
                    property int ridx: index

                    SectionHeader { text: qsTr("Recipient %1").arg(recCol.ridx + 1) }

                    TextField {
                        width: parent.width
                        label: qsTr("Address")
                        text: (dialog._tick, dialog._addr[recCol.ridx] || "")
                        inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhEmailCharactersOnly
                        EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                        EnterKey.onClicked: { focus = false; dialog._reresolve(recCol.ridx, text.trim()) }
                        onActiveFocusChanged: {
                            if (!activeFocus && text.trim() !== (dialog._addr[recCol.ridx] || ""))
                                dialog._reresolve(recCol.ridx, text.trim())
                        }
                    }

                    Label {
                        visible: (dialog._tick, dialog._cand[recCol.ridx] ? dialog._cand[recCol.ridx].length === 0 : true)
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        wrapMode: Text.WordWrap
                        text: qsTr("No key for this address.")
                        color: "#ff4d4d"
                        font.pixelSize: Theme.fontSizeSmall
                    }

                    Repeater {
                        model: (dialog._tick, dialog._cand[recCol.ridx] || [])
                        delegate: BackgroundItem {
                            width: recCol.width
                            height: kc.height + Theme.paddingMedium
                            highlighted: dialog._tick >= 0 && dialog._sel[recCol.ridx] === modelData.fingerprint
                            // Revoked/expired/signing-only keys are shown (so the
                            // situation is visible) but cannot be chosen.
                            enabled: dialog._selectable(modelData)
                            onClicked: { dialog._sel[recCol.ridx] = ("" + modelData.fingerprint); dialog._tick++ }
                            Column {
                                id: kc
                                x: Theme.horizontalPageMargin
                                width: parent.width - 2 * Theme.horizontalPageMargin
                                anchors.verticalCenter: parent.verticalCenter
                                Label {
                                    width: parent.width
                                    truncationMode: TruncationMode.Fade
                                    text: (dialog._sel[recCol.ridx] === modelData.fingerprint ? "● " : "○ ")
                                          + (modelData.name !== "" ? modelData.name : modelData.uid)
                                    color: dialog._statusColor(modelData)
                                    font.pixelSize: Theme.fontSizeSmall
                                }
                                Label {
                                    width: parent.width
                                    truncationMode: TruncationMode.Fade
                                    font.family: "monospace"
                                    font.pixelSize: Theme.fontSizeExtraSmall
                                    color: Theme.secondaryColor
                                    text: "0x" + modelData.keyId
                                          + (modelData.revoked ? "  · REVOKED" : modelData.expired ? "  · expired"
                                             : !modelData.canEncrypt ? "  · cannot encrypt" : "")
                                          + (modelData.email !== "" ? "  · " + modelData.email : "")
                                }
                                // The full fingerprint IS the identity — it is what
                                // an out-of-band check compares, so it must be
                                // visible right where the choice is made.
                                Label {
                                    width: parent.width
                                    wrapMode: Text.WrapAnywhere
                                    font.family: "monospace"
                                    font.pixelSize: Theme.fontSizeExtraSmall
                                    color: Theme.secondaryColor
                                    text: ("" + modelData.fingerprint).replace(/(.{4})/g, "$1 ").trim()
                                }
                            }
                        }
                    }
                }
            }
        }
        VerticalScrollDecorator {}
    }
}
