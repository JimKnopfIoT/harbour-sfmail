# harbour-sfmail

![harbour-sfmail](icon/preview-256.png)

> ⚠️ **PROOF OF CONCEPT / WORK IN PROGRESS — USE AT YOUR OWN RISK.**
> Provided **AS IS**, **without any warranty** of any kind, express or implied.
> No guarantee of correctness, security, fitness for any purpose or data safety.
> It handles cryptographic keys and e-mail — you alone are responsible for any
> use. See [`LICENSE`](LICENSE) for the full no-warranty terms (GPL-3.0).

**SF-Mail** is a **security-friendly e-mail client** for **Sailfish OS** with **built-in OpenPGP and
S/MIME** — its goal is to make encrypted e-mail genuinely easy: encrypt, decrypt and sign mail
(PGP/MIME, inline PGP *and* S/MIME), including encrypted attachments. Accounts, folders and messages
come from the system mail database (QMF), so the app sits next to the stock mail app and shares its
accounts.

> **SF-Mail = Security Friendly mail.** The "SF" is *not* short for Sailfish — it stands for the goal
> of making security (PGP and S/MIME) friendly and easy to use.

Since I'm not a developer, I let Claude Code write the whole thing
(even the icons are made by Claude Code).

## Opening mail from notifications (new in 0.5.1 — changes a system file)

**Up to and including 0.5.0**, tapping a "new mail" notification opened the **stock
Jolla mail client**, never SF-Mail — no matter which client you actually use. There
was no setting for it: the QMF notification plugin has its target compiled in as
`com.jolla.email.ui` → `openMessage`, and whichever program *owns* that D-Bus name
receives the tap.

**From 0.5.1** SF-Mail claims that name, so a notification tap opens the message in
SF-Mail. Because the same name also carries `mailto:` links and "share via e-mail",
those now come to SF-Mail as well — the app implements the full stock interface, so
nothing is silently dropped.

This is a **system-wide change, not a per-app preference.** Installing the package:

- adds `/etc/sailjail/permissions/EmailUi.permission`, which is what allows the
  sandboxed app to own the name (the sandbox itself stays fully in place);
- rewrites `/usr/share/dbus-1/services/com.jolla.email.ui.service` so a tap also
  starts SF-Mail when it isn't running. **The original is kept** next to it as
  `com.jolla.email.ui.service.sfmail-orig`, and a package trigger re-applies the
  change after a `jolla-email` update.

**Undoing it** — `rpm -e harbour-sfmail` restores the original file, and mail
notifications go back to the stock client. The stock client itself is never
modified, removed or disabled; it just no longer receives the tap while SF-Mail is
installed. (If both are running, whichever claimed the name first keeps it.)

**If you would rather not have this**, **0.5.0** remains available under
[Releases](../../releases) — it is the last version that leaves the notification
target alone. Be aware of what you give up: it predates everything released since,
including the fix that makes blind copies work at all (before 0.6.3 a blind
recipient received a message encrypted to everyone but them, and could not open
it), moving messages between folders, retrying a stuck outbox, and the S/MIME
certificate selection.

## Blind copies and encrypted subjects (new in 0.6.9 — visible to your recipients)

Encryption protects the body, not the envelope. Two consequences used to leak, and
0.6.9 changes both — in ways your correspondents will notice.

**Blind copies.** A single encrypted message names **every** recipient key in the
clear: OpenPGP writes one key packet per recipient, S/MIME one `RecipientInfo` per
certificate. Anyone who receives such a message can read that list — so a blind copy
was only blind in the headers. SF-Mail therefore sends **one message per audience**:
the open recipients get theirs, every blind copy gets its own, each encrypted only to
the keys that belong in it. No recipient learns of any other, not even how many there
were.

What you will notice:

- Sending to blind copies produces **one message per blind recipient** in *Sent*.
- A blind copy needs the recipient's key or certificate, like any other. Without it
  the message is **not sent** — SF-Mail never falls back to plain text silently.
- **Inline PGP cannot do this** (one armoured block, one message) and refuses a blind
  copy; use PGP/MIME.

**Encrypted subject.** The subject travelled in the clear past every server on the
way, which often says more than the body. Encrypted mail now carries the real subject
**inside** the encryption ([protected
headers](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-header-protection),
as Thunderbird does) and shows `...` on the outside. The same mechanism carries the
recipients, so a blind copy still sees whom the message was addressed to.

The price is real and worth knowing before you use it:

- Clients that do not implement protected headers (Outlook, for example) show `...`
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

## Why a bundled GnuPG

The system `gpg` on the target devices is too old to read modern keyrings
(`pubring.kbx` + `private-keys-v1.d`), so the app bundles a **modern GnuPG 2.2**
stack under its own prefix (`/usr/share/harbour-sfmail/gpg/…`) and talks to it
through a small QProcess wrapper plugin (`SFMail.Gpg`, QML singleton `Gpg`). The
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

The bundled GnuPG binaries are checked in under `stack/stage-aarch64/` and
`stack/stage-armv7hl/` so the RPM builds out of the box. To rebuild the GnuPG
stack from the upstream tarballs in `stack/src/`, see `stack/build-stack.sh`.

## License

**GPL-3.0-or-later** — see [`LICENSE`](LICENSE).

The app bundles GnuPG and its libraries (GPL / LGPL). Their licenses, versions
and corresponding upstream source are documented in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md); the exact source tarballs the
bundled binaries were built from are included under `stack/src/`.
