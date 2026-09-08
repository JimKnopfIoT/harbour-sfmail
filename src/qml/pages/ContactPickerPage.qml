import QtQuick 2.6
import Sailfish.Silica 1.0
import org.nemomobile.contacts 1.0
import SFMail.Gpg 1.0

// Address-book picker: the addresses the user has remembered, followed by the
// contacts that carry an e-mail address, with live search. Result via
// picked(email). Read-only towards the contacts — never modifies them.
//
// The rows are built here rather than bound straight to the contact model. Two
// reasons, both of them things that model cannot do for us:
//
//  * Order. It sorts by whichever name part the platform is configured to sort
//    by, and that property is read-only for us. Showing "first name first"
//    while sorting by last name yields a list that is sorted and still looks
//    random. So we show the name in the same order it is sorted by, and sort
//    our own rows accordingly.
//  * Search. Its filter needs a value from this page, and a value cannot cross
//    into it from a header component: ids declared inside a header are not
//    visible outside it, so that binding never ran and typing did nothing at
//    all. Filtering our own rows has no such boundary.
//
// One row per address, not per contact: a contact with three addresses is three
// rows. That shows the addresses instead of hiding them behind a menu, and lets
// the search match the address as well as the name. The other way round, one
// address held in several places is still ONE row — the places are named under
// it, so the list says where an address comes from instead of repeating it.
Page {
    id: page
    allowedOrientations: defaultAllowedOrientations
    signal picked(string email)

    property string searchText: ""
    property var _allRows: []          // everything; `entries` holds the matches

    // Sort by the same name part the platform sorts by; fall back to the last
    // name, which is what a paper address book does.
    readonly property bool _lastNameFirst: ("" + people.sortProperty) === "lastName"

    ListModel { id: entries }

    // Only for the wording of "where is this address known from" — the contact
    // model of this page is the one below, so this one loads none of its own.
    AddressKnowledge { id: known; contacts: false }

    PeopleModel {
        id: people
        filterType: PeopleModel.FilterAll
        requiredProperty: PeopleModel.EmailAddressRequired
        // The model fills in batches; rebuilding on every batch would walk the
        // whole list dozens of times, so coalesce into one pass.
        onPopulatedChanged: rebuildTimer.restart()
        onCountChanged: rebuildTimer.restart()
    }
    Timer {
        id: rebuildTimer
        interval: 150
        onTriggered: page._rebuild()
    }

    // A role the model does not carry comes back undefined; printing that
    // verbatim would put the word "undefined" on screen.
    function _str(v) { return (v === undefined || v === null) ? "" : ("" + v) }

    // "Lastname Firstname" when sorting by last name, "Firstname Lastname"
    // otherwise; empty when the contact carries no name (company-only entries).
    function _displayName(first, last, label) {
        var f = page._str(first).trim(), l = page._str(last).trim()
        if (f === "" && l === "") return page._str(label).trim()
        return (page._lastNameFirst ? (l + " " + f) : (f + " " + l)).trim()
    }

    function _sortKey(row) {
        var k = ("" + row.name).trim()
        return (k !== "" ? k : ("" + row.address)).toLowerCase()
    }

    function _byName(a, b) {
        var ka = page._sortKey(a), kb = page._sortKey(b)
        if (ka !== kb) return ka < kb ? -1 : 1
        var aa = ("" + a.address).toLowerCase(), ab = ("" + b.address).toLowerCase()
        return aa < ab ? -1 : aa > ab ? 1 : 0
    }

    function _rebuild() {
        // One row per address, no matter how many places hold it: the same
        // address from the address book, from a key and from the remembered
        // list is ONE person, and three rows for them is what made the list
        // look like it was repeating itself. The places are merged into the
        // row instead and named underneath it.
        var rows = []
        var byAddr = {}

        function put(addr, name, source) {
            var a = ("" + addr).trim()
            if (a.indexOf("@") < 1) return
            var low = a.toLowerCase()
            var r = byAddr[low]
            if (!r) {
                r = { "name": page._str(name).trim(), "address": a,
                      "remembered": false, "pgp": false, "smime": false, "book": false }
                byAddr[low] = r
                rows.push(r)
            } else if (r.name === "") {
                r.name = page._str(name).trim()      // first name we get wins
            }
            r[source] = true
        }

        // Order of the sources decides which name is shown and, for equal sort
        // keys, which row comes first: what the user remembered on purpose,
        // then everyone we hold a key or certificate for (addresses already
        // worked with, often not in the address book at all), then the book.
        var mine = Gpg.rememberedAddresses()
        for (var m = 0; m < mine.length; ++m)
            put(mine[m].address, mine[m].name, "remembered")

        // Revoked and expired keys still count here: a stale key says nothing
        // about whether the address is still good.
        var keys = Gpg.publicKeys()
        for (var k = 0; k < keys.length; ++k) {
            var addrs = keys[k].emails
            if (addrs && addrs.length > 0) {
                for (var e = 0; e < addrs.length; ++e) put(addrs[e], keys[k].name, "pgp")
            } else {
                put(keys[k].email, keys[k].name, "pgp")
            }
        }
        if (Gpg.smimeEnabled && Smime.available) {
            var certs = Smime.listCerts()
            for (var ci = 0; ci < certs.length; ++ci) {
                var ce = certs[ci].emails
                for (var cj = 0; ce && cj < ce.length; ++cj) put(ce[cj], certs[ci].uid, "smime")
            }
        }

        // get(row) hands us every role of one contact in a single call, so this
        // is one pass over a list of at most a few hundred entries — done when
        // the model is ready, not per keystroke.
        for (var i = 0; i < people.count; ++i) {
            var c = people.get(i)
            if (!c) continue
            var name = page._displayName(c.firstName, c.lastName, c.displayLabel)
            var details = c.emailDetails
            if (!details) continue
            for (var j = 0; j < details.length; ++j)
                put(details[j].address, name, "book")
        }

        // Remembered rows first, then keyed ones, then the rest; alphabetical
        // within each group.
        function rank(r) { return r.remembered ? 0 : ((r.pgp || r.smime) ? 1 : 2) }
        rows.sort(function(a, b) {
            var ra = rank(a), rb = rank(b)
            if (ra !== rb) return ra - rb
            return page._byName(a, b)
        })
        for (var n = 0; n < rows.length; ++n)
            rows[n].sources = known.sourceNames(rows[n]).join(", ")

        page._allRows = rows
        page._applyFilter()
    }

    function _applyFilter() {
        var q = page.searchText.trim().toLowerCase()
        entries.clear()
        for (var i = 0; i < page._allRows.length; ++i) {
            var r = page._allRows[i]
            if (q !== ""
                && ("" + r.name).toLowerCase().indexOf(q) < 0
                && ("" + r.address).toLowerCase().indexOf(q) < 0) continue
            entries.append(r)
        }
    }

    onSearchTextChanged: page._applyFilter()
    Component.onCompleted: page._rebuild()

    SilicaListView {
        id: list
        anchors.fill: parent
        model: entries

        PullDownMenu {
            MenuItem {
                text: qsTr("Remembered addresses")
                onClicked: {
                    var p = pageStack.push(Qt.resolvedUrl("RememberedAddressesPage.qml"))
                    // Editing there changes what belongs at the top of this list.
                    p.statusChanged.connect(function() {
                        if (p.status === PageStatus.Deactivating) page._rebuild()
                    })
                }
            }
        }

        header: Column {
            width: parent.width
            PageHeader { title: qsTr("Address book") }
            SearchField {
                width: parent.width
                placeholderText: qsTr("Search contacts")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                // The text has to land on the page: a header is its own
                // component, and nothing outside it can read an id declared in
                // here — that is what made this field do nothing.
                onTextChanged: page.searchText = text
                Component.onCompleted: forceActiveFocus()
            }
        }

        delegate: ListItem {
            id: item
            contentHeight: cc.height + Theme.paddingMedium

            onClicked: { page.picked("" + model.address); pageStack.pop() }

            Column {
                id: cc
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                Label {
                    width: parent.width; truncationMode: TruncationMode.Fade
                    text: ("" + model.name) !== "" ? model.name : model.address
                    color: model.remembered ? Theme.highlightColor : Theme.primaryColor
                }
                Label {
                    width: parent.width; truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: (("" + model.name) !== "" ? ("" + model.address) : "")
                          + (("" + model.sources) !== ""
                             ? ((("" + model.name) !== "" ? "  ·  " : "") + model.sources)
                             : "")
                    visible: text !== ""
                }
            }

            // Only a remembered row can be forgotten — the address book itself
            // is none of our business.
            menu: model.remembered ? forgetMenu : null
            Component {
                id: forgetMenu
                ContextMenu {
                    MenuItem {
                        text: qsTr("Forget this address")
                        onClicked: { Gpg.forgetAddress("" + model.address); page._rebuild() }
                    }
                }
            }
        }

        ViewPlaceholder {
            enabled: entries.count === 0
            text: page.searchText !== "" ? qsTr("No matches")
                                         : qsTr("No contacts with an e-mail address")
        }
        VerticalScrollDecorator {}
    }
}
