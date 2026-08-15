# harbour-sfmail

![harbour-sfmail](icon/preview-256.png)

**SF-Mail** is an unofficial, **security-friendly e-mail client** for **Sailfish OS** with **built-in OpenPGP and
S/MIME** — its goal is to make encrypted e-mail genuinely easy: encrypt, decrypt and sign mail
(PGP/MIME, inline PGP *and* S/MIME), including encrypted attachments. Accounts, folders and messages
come from the system mail database (QMF), so the app sits next to the stock mail app and shares its
accounts.

> **SF-Mail = Security Friendly mail.** The "SF" is *not* short for Sailfish — it stands for the goal
> of making security (PGP and S/MIME) friendly and easy to use.

Since I'm not a developer, I let Claude Code write the whole thing
(even the icons are made by Claude Code).

## Opening mail from notifications (changes a system file)

Tapping a "new mail" notification is delivered to whichever program **owns** the
D-Bus name `com.jolla.email.ui` — the QMF notification plugin has that target
compiled in, and the same name also carries `mailto:` links and "share via
e-mail". Out of the box that is the stock Jolla mail client, with no setting to
change it.

SF-Mail can take that name over, so taps, `mailto:` and sharing open
in SF-Mail — the app implements the full stock interface, so nothing is silently
dropped. A switch controls this: *About → System → "Open mail
notifications in this app"*, on by default. Switching it off hands everything
back to the client that owned it before SF-Mail was installed — the D-Bus
activation entry points at a small dispatcher that reads this setting on every
activation.

This is a **system-wide change, not a per-app preference.** Installing the package:

- adds `/etc/sailjail/permissions/EmailUi.permission`, which is what allows the
  sandboxed app to own the name (the sandbox itself stays fully in place);
- rewrites `/usr/share/dbus-1/services/com.jolla.email.ui.service` so a tap also
  starts SF-Mail when it isn't running. **The original is kept** next to it as
  `com.jolla.email.ui.service.sfmail-orig`, and a package trigger re-applies the
  change after a `jolla-email` update.

**Undoing it** — turn the switch off, or `rpm -e harbour-sfmail`, which restores
the original file; either way mail notifications go back to the previous client. The stock client itself is never
modified, removed or disabled; it just no longer receives the tap while SF-Mail is
installed. (If both are running, whichever claimed the name first keeps it.)

**If you would rather not have this**, simply leave the switch off.

## Blind copies and encrypted subjects (visible to your recipients)

Encryption protects the body, not the envelope. SF-Mail closes two leaks that
follow from that — in ways your correspondents will notice.

**Blind copies.** A single encrypted message names **every** recipient key in the
clear: OpenPGP writes one key packet per recipient, S/MIME one `RecipientInfo` per
certificate. Anyone who receives such a message can read that list — so a blind copy
would only be blind in the headers. SF-Mail therefore sends **one message per audience**:
the open recipients get theirs, every blind copy gets its own, each encrypted only to
the keys that belong in it. No recipient learns of any other, not even how many there
were.

What you will notice:

- Sending to blind copies produces **one message per blind recipient** in *Sent*.
- A blind copy needs the recipient's key or certificate, like any other. Without it
  the message is **not sent** — SF-Mail never falls back to plain text silently.
- **Inline PGP cannot do this** (one armoured block, one message) and refuses a blind
  copy; use PGP/MIME.

**Encrypted subject.** A subject sent in the clear passes every server on the
way and often says more than the body. Encrypted mail therefore carries the real subject
**inside** the encryption ([protected
headers](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-header-protection),
as other clients do) and shows `...` on the outside. The same mechanism carries the
recipients, so a blind copy still sees whom the message was addressed to.

The price is real and worth knowing before you use it:

- Clients that do not implement protected headers show `...`
  as the subject, and their replies come back as `Re: ...`.
- Server-side search and threading only ever see the placeholder.
- In the message list SF-Mail also shows `...` until the message is decrypted; the
  real subject appears when you open it.

Signed-only mail is unaffected — there is nothing to hide from someone who can read
the body anyway.

## Features

- Accounts + per-account folder list (swipe left in a mailbox), combined inbox
- Read / delete messages, raw header view with sender checks
  (active SPF/DMARC via DNS, From↔Return-Path mismatch, optional DNS blacklists —
  only the sender's IP/domain are ever looked up, nothing of yours)
- Attachments (plain, PGP and S/MIME) with their size — **open with…** or
  **save as…** to a folder you pick; large attachments download on demand
- **Blind copies stay blind** — one message per audience, so no recipient can read
  the others off the encryption; encrypted subjects via protected headers (see above)
- **OpenPGP** — encrypt (+ optional sign), decrypt by tap (PGP/MIME with a
  passphrase dialog, and inline PGP), signature status, PGP/MIME sending
  (RFC 3156, `multipart/encrypted`) with attachments
- **Easy key management** — **create** your own RSA-4096 key right in the app (a
  strong passphrase is enforced), import / export / details, **back up** the secret
  key, **extend** the expiry, **revoke** (a protected revocation certificate is
  created for you; revoking is a deliberate two-step with confirmation), and
  **publish** to `keys.openpgp.org`. Keyserver lookup never auto-imports — it shows
  the fingerprint, you decide. When generating a key the exact command is shown for
  transparency.
- **S/MIME** — decrypt by tap, sign and/or encrypt outgoing mail (CMS,
  `application/pkcs7-mime`) with attachments. Certificate management: **create** your
  own self-signed RSA-4096 certificate (with the `emailProtection` /
  `keyEncipherment` e-mail attributes), import your own `.p12`, **back it up** as a
  `.p12`, import a sender's certificate from a signed message, automatic trust-chain
  completion
- Crypto type follows the conversation: replies match the received mail
  (S/MIME → S/MIME, PGP → PGP, plain → plain); for a new message you only choose
  when both PGP and S/MIME are actually possible for sender and recipients
- 1-tap key import with safety checks — warns about revoked/expired keys, a key
  already present, a *different* key already stored for the address, and whether
  the key matches the sender; never imports without your confirmation
- Address-book picker per recipient, with a per-recipient crypto hint
  (🔑 PGP / 📜 S/MIME / no key)
- German + English UI (follows the system language); localized folder names
- **Key hygiene & privacy** — the bundled GnuPG agent is hardened so unlocked keys
  are not kept in memory between operations; after importing a key file you can have
  it securely deleted from the device; backups are passphrase-protected and the app
  reminds you to move them off-device; a debug log can be turned on or off under
  *About → Diagnostics* (off for normal use)

## Trust model

Trust in SF-Mail is a decision made on the device, not one delegated to an
authority. The app is built for encrypted mail across trust boundaries — with
or without a CA on the other side — so it carries no PKI of its own:
identities you create yourself and identities you import stand on the same
footing, and each becomes trusted the moment you, having seen its
fingerprint, say so. This holds for S/MIME exactly as for PGP. Revocation
lists belong to the delegated-trust world and are consequently not consulted.

## Why a bundled GnuPG

The system `gpg` on the target devices is too old to read modern keyrings
(`pubring.kbx` + `private-keys-v1.d`), so the app bundles a **maintained GnuPG
2.5** stack (2.5.21, with current libgcrypt/libksba/libassuan) under its own
prefix (`/usr/share/harbour-sfmail/gpg/…`). OpenPGP is driven through the
GpgME++/QGpgME C++ bindings (gpgme 1.18) in the app's plugin (`SFMail.Gpg`, QML
singleton `Gpg`); only S/MIME shells out to `gpgsm`/OpenSSL. The
app uses its **own keyring** at `~/.local/share/sfmail/harbour-sfmail/gnupg`,
entirely separate from the system keystore. S/MIME uses `gpgsm` from the same
bundled stack (plus an OpenSSL helper for `.p12` handling) with its own store
under `~/.local/share/sfmail/harbour-sfmail/smime`.

## Build

Requires the Sailfish OS Platform SDK. Build the RPM per target:

```sh
# aarch64
mb2 -t SailfishOS-5.0.0.62-aarch64.default build
# armv7hl (SFOS 4.6)
mb2 -t SailfishOS-4.6.0.13-armv7hl.default build
```

RPMs are written to `RPMS/`. Install on the device with
`rpm -U --force <rpm>`.

The bundled GnuPG binaries are checked in under `stack/stage-modern-aarch64/` and
`stack/stage-modern-armv7hl/` so the RPM builds out of the box. To rebuild the GnuPG
stack from the upstream tarballs in `stack/src/`, see `stack/build-stack.sh`.

## License

**GPL-3.0-or-later** — see [`LICENSE`](LICENSE).

The app bundles GnuPG and its libraries (GPL / LGPL). Their licenses, versions
and corresponding upstream source are documented in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md); the exact source tarballs the
bundled binaries were built from are included under `stack/src/`.
