.pragma library

// Who is a message REALLY encrypted to?
//
// A blind copy is invisible in the headers only. The encryption layer names
// every recipient: OpenPGP writes one PKESK packet per recipient key (the key
// id is in the clear), S/MIME one RecipientInfo per certificate. So a recipient
// key that resolves to an address which appears in neither To: nor Cc: is a
// blind copy — and once the key is in our keyring, we can also name the person.
//
// This is shared by CryptoInfoPage (OpenPGP) and SmimeInfoPage (S/MIME) so both
// classify identically.

// Pull every e-mail address out of a string like "Name <a@b.tld>" or "a@b.tld".
function addressesIn(text) {
    var out = [];
    if (!text) return out;
    var re = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
    var m;
    while ((m = re.exec("" + text)) !== null) out.push(m[0].toLowerCase());
    return out;
}

// Header values (arrays or single strings) → flat list of lowercase addresses.
function addressList(values) {
    var out = [];
    if (!values) return out;
    var list = (values instanceof Array) ? values : [values];
    for (var i = 0; i < list.length; ++i) out = out.concat(addressesIn(list[i]));
    return out;
}

function _intersects(a, b) {
    for (var i = 0; i < a.length; ++i)
        for (var j = 0; j < b.length; ++j)
            if (a[i] === b[j]) return true;
    return false;
}

// Role of ONE recipient key/certificate.
//   identities — UID strings (PGP) or the certificate subject (S/MIME)
//   known      — is it in our keyring/store? If not we cannot name it at all
//   visible    — addresses taken from To: and Cc:
//   sender     — address taken from From:
// Returns "visible" | "sender" | "blind" | "unknown".
function roleOf(identities, known, visible, sender) {
    if (!known) return "unknown";
    var mine = addressList(identities);
    if (mine.length === 0) return "unknown";
    if (_intersects(mine, addressList(visible))) return "visible";
    if (_intersects(mine, addressList(sender))) return "sender";
    return "blind";
}

// Roles for a whole recipient list. `identitiesOf` and `knownOf` adapt the two
// engines' differing field names.
function rolesFor(recipients, identitiesOf, knownOf, visible, sender) {
    var out = [];
    for (var i = 0; i < (recipients ? recipients.length : 0); ++i)
        out.push(roleOf(identitiesOf(recipients[i]), knownOf(recipients[i]), visible, sender));
    return out;
}

function countRole(roles, role) {
    var n = 0;
    for (var i = 0; i < roles.length; ++i) if (roles[i] === role) n++;
    return n;
}
