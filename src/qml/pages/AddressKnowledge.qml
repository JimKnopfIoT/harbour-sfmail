import QtQuick 2.6
import org.nemomobile.contacts 1.0
import SFMail.Gpg 1.0

// Where is this address already known? An address the user is about to put on
// the remembered list is often one the device already holds — in the address
// book, or behind a key or a certificate. Adding it again is not wrong, but it
// is a second copy the user has to keep in step by hand, so the places it is
// known are worth saying out loud before the copy is made.
//
// Every page that offers to remember an address asks here, so the wording is
// written once. Instantiate it OUTSIDE a layout container: it is an Item and a
// Column would give it a row of its own.
//
// The two expensive sources — the key ring and the certificate store — are read
// once and cached; `refresh()` drops the cache. The address book is only loaded
// when `contacts` is true, because building it costs a pass over every contact
// on the device and a page that only needs the cheap sources should not pay it.
Item {
    id: root
    visible: false
    width: 0
    height: 0

    // Look in the address book too. Pages that already hold a contact model of
    // their own leave this off and pass their own findings to describeFlags().
    property bool contacts: true

    // Bumped whenever the answer to sourcesOf() may have changed — the contact
    // model finished filling, or the cache was dropped. Bind to it, or reload
    // on it: a plain function call in a delegate would never be re-evaluated.
    property int revision: 0

    property var _keyAddrs: null        // lower-cased address -> true
    property var _certAddrs: null
    property var _bookAddrs: null

    function refresh() {
        _keyAddrs = null
        _certAddrs = null
        _bookAddrs = null
        if (contactLoader.item) contactLoader.item.rebuild()
        revision = revision + 1
    }

    function _collect(list, addr) {
        var a = ("" + addr).trim().toLowerCase()
        if (a.indexOf("@") > 0) list[a] = true
    }

    function _keys() {
        if (_keyAddrs === null) {
            var m = {}
            var keys = Gpg.publicKeys()
            for (var k = 0; k < keys.length; ++k) {
                var e = keys[k].emails
                if (e && e.length > 0) {
                    for (var i = 0; i < e.length; ++i) root._collect(m, e[i])
                } else {
                    root._collect(m, keys[k].email)
                }
            }
            _keyAddrs = m
        }
        return _keyAddrs
    }

    function _certs() {
        if (_certAddrs === null) {
            var m = {}
            if (Gpg.smimeEnabled && Smime.available) {
                var certs = Smime.listCerts()
                for (var c = 0; c < certs.length; ++c) {
                    var e = certs[c].emails
                    for (var i = 0; e && i < e.length; ++i) root._collect(m, e[i])
                }
            }
            _certAddrs = m
        }
        return _certAddrs
    }

    // Which places hold this address. `remembered` is read live rather than
    // cached: the user changes that list from the very pages that ask here.
    function sourceFlags(address) {
        var a = ("" + address).trim().toLowerCase()
        var f = { "remembered": false, "pgp": false, "smime": false, "book": false }
        if (a.indexOf("@") < 1) return f

        var mine = Gpg.rememberedAddresses()
        for (var i = 0; i < mine.length; ++i) {
            if (("" + mine[i].address).trim().toLowerCase() === a) { f.remembered = true; break }
        }
        f.pgp = !!root._keys()[a]
        f.smime = !!root._certs()[a]
        f.book = root.contacts && _bookAddrs !== null && !!_bookAddrs[a]
        return f
    }

    // The places, named, in the order a reader cares about them.
    function sourceNames(flags) {
        var out = []
        if (flags.remembered) out.push(qsTr("Remembered addresses"))
        if (flags.pgp) out.push(qsTr("PGP key"))
        if (flags.smime) out.push(qsTr("S/MIME certificate"))
        if (flags.book) out.push(qsTr("Address book"))
        return out
    }

    // One line for the user, empty when the address is new here.
    function describeFlags(flags) {
        var names = root.sourceNames(flags)
        return names.length === 0 ? "" : qsTr("Already known: %1").arg(names.join(", "))
    }

    function describe(address) {
        return root.describeFlags(root.sourceFlags(address))
    }

    // True while the address book has not been read yet, so a page can say it
    // is still looking instead of claiming the address is unknown.
    readonly property bool checking: contacts && _bookAddrs === null

    function statusText(address) {
        var line = root.describe(address)
        if (line !== "") return line
        return root.checking ? qsTr("Looking for this address…")
                             : qsTr("Not known here yet")
    }

    Loader {
        id: contactLoader
        active: root.contacts
        sourceComponent: Component {
            Item {
                function rebuild() { buildTimer.restart() }
                PeopleModel {
                    id: people
                    filterType: PeopleModel.FilterAll
                    requiredProperty: PeopleModel.EmailAddressRequired
                    // The model fills in batches; one pass per batch would walk
                    // every contact dozens of times.
                    onPopulatedChanged: buildTimer.restart()
                    onCountChanged: buildTimer.restart()
                }
                Timer {
                    id: buildTimer
                    interval: 150
                    onTriggered: {
                        var m = {}
                        for (var i = 0; i < people.count; ++i) {
                            var c = people.get(i)
                            if (!c) continue
                            var details = c.emailDetails
                            for (var j = 0; details && j < details.length; ++j)
                                root._collect(m, details[j].address)
                        }
                        root._bookAddrs = m
                        root.revision = root.revision + 1
                    }
                }
                Component.onCompleted: buildTimer.restart()
            }
        }
    }
}
