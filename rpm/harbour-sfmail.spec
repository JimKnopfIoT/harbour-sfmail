# Keep the local machine name out of the RPM header (Build Host) — the
# released packages must not leak the build environment.
%global _buildhost reproducible-builder

Name:       harbour-sfmail
Summary:    E-mail client with built-in OpenPGP for Sailfish OS
Version:    0.8.3
Release:    1
Group:      Applications/Productivity
License:    GPLv3+
URL:        https://github.com/JimKnopfIoT/harbour-sfmail
Source0:    %{name}-%{version}.tar.bz2

BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Qml)
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(sailfishapp) >= 1.0.2
BuildRequires:  desktop-file-utils

Requires:   sailfishsilica-qt5 >= 0.10.9
Requires:   nemo-qml-plugin-email-qt5

%description
A full e-mail client built on the Qt Messaging Framework (Nemo.Email), with
OpenPGP encryption / signing integrated. Development version, installed in
parallel to the stable harbour-sfmail-pgp companion app.

%prep
%setup -q -n %{name}-%{version}

%build
# Single source of truth for the version shown in-app: inject the spec version.
echo '#define SFMAIL_VERSION "%{version}"' > mailcrypto/sfmail_version.h
# Force the version TU to recompile so the new version is actually baked in
# (incremental in-source builds otherwise keep a stale GpgEngine.o).
touch mailcrypto/GpgEngine.cpp
%qmake5
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%qmake5_install

# Sailjail only lets a sandboxed app own <OrganizationName>.<ApplicationName>.
# Serving com.jolla.email.ui (what the notification plugin calls) therefore needs
# an explicit permission profile; the app's .desktop lists it as "EmailUi".
mkdir -p %{buildroot}%{_sysconfdir}/sailjail/permissions
install -m 644 rpm/EmailUi.permission \
    %{buildroot}%{_sysconfdir}/sailjail/permissions/EmailUi.permission

# Bundle the modern GnuPG 2.2 stack under our OWN app prefix, so the sandbox
# (which hides other apps' /usr/share/<app>) can reach it. The bundled gpg's
# RPATH points at the old prefix; that path is absent here, so the loader falls
# back to LD_LIBRARY_PATH (set by the plugin) → our own gpg/lib.
# The stack is architecture-specific (cross-built per target).
%ifarch armv7hl armv7l
%define stackstage stack/stage-modern-armv7hl
%else
%define stackstage stack/stage-modern-aarch64
%endif
# The switchboard the D-Bus activation entry points at; the About -> System
# switch writes the marker file it reads (absent = ON, see rpm/mailui-dispatch).
install -D -m 755 rpm/mailui-dispatch \
    %{buildroot}%{_datadir}/%{name}/bin/mailui-dispatch

mkdir -p %{buildroot}%{_datadir}/%{name}/gpg
cp -a %{stackstage}/usr/share/harbour-sfmail-pgp/bin \
      %{stackstage}/usr/share/harbour-sfmail-pgp/lib \
      %{stackstage}/usr/share/harbour-sfmail-pgp/libexec \
      %{stackstage}/usr/share/harbour-sfmail-pgp/share \
      %{buildroot}%{_datadir}/%{name}/gpg/

# --- Slim the bundled GnuPG stack -------------------------------------------
# Ship only what the app actually uses at runtime (libgpgme + the C++/Qt
# bindings libgpgmepp/libqgpgme + gpg, gpg-agent, gpgsm, dirmngr, gpgconf,
# openssl, pinentry, gpg-protect-tool) — a smaller RPM AND a smaller attack
# surface. (PGP goes through the GpgME++/QGpgME bindings since 0.5.0; the
# locale prune is kept for size — errors are typed now, not parsed from stderr.)
GPGDIR=%{buildroot}%{_datadir}/%{name}/gpg
rm -rf "$GPGDIR"/lib/cmake
for b in dirmngr-client dumpsexp gpg-error gpg-error-config gpgme-config \
         gpgme-json gpgme-tool gpgparsemail gpgrt-config gpgscm gpgsplit gpgv \
         hmac256 kbxutil ksba-config libassuan-config libgcrypt-config mpicalc \
         npth-config watchgnupg yat2m gpg-connect-agent; do
    rm -f "$GPGDIR/bin/$b"
done
for x in scdaemon gpg-wks-client gpg-check-pattern gpg-preset-passphrase; do
    rm -f "$GPGDIR/libexec/$x"
done
rm -rf "$GPGDIR"/share/locale "$GPGDIR"/share/info "$GPGDIR"/share/man \
       "$GPGDIR"/share/doc "$GPGDIR"/share/aclocal "$GPGDIR"/share/common-lisp

# Strip our own binaries so no build-time paths (developer home dir / name)
# remain in the shipped app.
strip %{buildroot}%{_bindir}/%{name} || true
strip %{buildroot}%{_libdir}/qt5/qml/SFMail/Gpg/libsfmailgpg.so || true

desktop-file-validate %{buildroot}%{_datadir}/applications/%{name}.desktop || echo "warn"

for size in 86x86 108x108 128x128 172x172; do
    if [ -f src/icons/${size}/%{name}.png ]; then
        install -D -m 0644 src/icons/${size}/%{name}.png \
            %{buildroot}%{_datadir}/icons/hicolor/${size}/apps/%{name}.png
    fi
done

# --- Notification hand-off ---------------------------------------------------
# The QMF notification plugin has the target of a "new mail" tap compiled in
# (com.jolla.email.ui → openMessage); the only way to receive it is to own that
# bus name. Owning it at runtime is not enough on a cold start, so the D-Bus
# activation entry has to point here too — and that file belongs to jolla-email,
# which is why it is rewritten in a scriptlet instead of shipped in %%files (an
# RPM file conflict would block installation outright).
#
# The original is kept next to it and put back on uninstall, so removing this
# package hands mail notifications straight back to the stock client.
%define emailsvc %{_datadir}/dbus-1/services/com.jolla.email.ui.service
%define emailsvcbak %{emailsvc}.sfmail-orig

%post
if [ -f %{emailsvc} ] && [ ! -f %{emailsvcbak} ]; then
    cp -a %{emailsvc} %{emailsvcbak}
fi
cat > %{emailsvc} <<'SFMAIL_EOF'
[D-BUS Service]
Interface=/com/jolla/email/ui
Name=com.jolla.email.ui
Exec=%{_datadir}/%{name}/bin/mailui-dispatch
SFMAIL_EOF

# A jolla-email update reinstalls its own copy of the service file and would
# silently take the notifications back. Re-claim it whenever that package is
# touched, so the setting survives OS updates.
%triggerin -- jolla-email
if [ -f %{emailsvc} ] && [ ! -f %{emailsvcbak} ]; then
    cp -a %{emailsvc} %{emailsvcbak}
fi
cat > %{emailsvc} <<'SFMAIL_EOF'
[D-BUS Service]
Interface=/com/jolla/email/ui
Name=com.jolla.email.ui
Exec=%{_datadir}/%{name}/bin/mailui-dispatch
SFMAIL_EOF

%postun
# $1 == 0 is a real uninstall; on an upgrade the old package's %%postun runs
# AFTER the new one's %%post, so restoring there would undo the fresh claim.
if [ "$1" -eq 0 ]; then
    if [ -f %{emailsvcbak} ]; then
        mv -f %{emailsvcbak} %{emailsvc}
    fi
fi

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%{_datadir}/%{name}
%{_libdir}/qt5/qml/SFMail/Gpg
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.png
%{_sysconfdir}/sailjail/permissions/EmailUi.permission

%changelog
* Sat Aug 15 2026 harbour-sfmail contributors 0.8.3-1
- Key selection tightened, prompted by an external review. The recipient key
  dialog shows each key's full fingerprint (the identity an out-of-band check
  compares), no longer pre-selects a key when the choice is ambiguous, and
  revoked/expired/signing-only keys cannot be chosen at all. Recipient checks
  count only keys that can actually encrypt, so a signing-only key fails at
  selection time instead of inside the encrypt job. Encrypt-to-self prefers
  the account's own secret key, so the Sent copy is always readable. An
  unused engine entry point that auto-imported keyserver results was removed;
  the one remaining lookup path never imports without confirmation. The
  README documents the trust model.

* Sat Aug 15 2026 harbour-sfmail contributors 0.8.2-1
- Passphrase hardening in the app process itself. The process is no longer
  ptrace-able or dumpable by other processes of the same user (it holds
  passphrases and, briefly, decrypted key material); a crash therefore leaves
  no core dump - the in-app log keeps its crash marker. All passphrase fields
  are marked as sensitive input so the keyboard never learns them, and they
  clear themselves when the dialog leaves the screen or the app loses the
  foreground. In-memory passphrase copies are wiped once handed over.

* Fri Aug 14 2026 harbour-sfmail contributors 0.8.1-1
- S/MIME hardening, prompted by an external review. Signing exported the private
  key into a temporary unencrypted PEM file and passed passphrases to openssl as
  "-passin pass:..." on the command line - and a process command line is readable
  by every other process on the system. Passphrases now travel through the child
  process environment only, and private key material no longer touches the disk
  at all: it is piped between gpgsm and openssl in memory, in every path
  (signing, .p12 import, certificate generation), and wiped after use. What
  remains on disk is public certificates and the passphrase-protected .p12.

* Fri Aug 14 2026 harbour-sfmail contributors 0.8.0-1
- The bundled GnuPG stack moves from the end-of-life 2.2 line (2.2.43, no fixes
  since the end of 2024) to the maintained stable line: GnuPG 2.5.21 with
  current libgcrypt, libksba, libgpg-error, npth and libassuan. This closes
  CVE-2025-68973, an out-of-bounds write in the armor parser - the code path
  every incoming encrypted or signed message walks through. Keyrings are
  untouched; existing keys keep working.
- Backing up a secret key to Documents works again. It had been broken since the
  0.5.0 engine port (the export called an API that refuses secret material) and
  the error was misreported as a wrong passphrase.
- The notification hand-off is now a switch (About -> System), default on.
  Switching it off hands "new mail" taps, mailto: links and "share via email"
  back to the client that owned them before this package was installed.
- Completed the German translation (43 missing strings) and silenced a bogus
  gpgsm version complaint in the journal.

* Fri Aug 14 2026 harbour-sfmail contributors 0.7.1-1
- Fixed the crash that could take the app down after reading a message. Deleting
  several messages right after opening one killed the app at the end of the
  countdown, and the messages were still there afterwards - it never got as far
  as deleting them. The cause was ours: EmailAgent looks like an ordinary QML
  element, but the mail plugin keeps a single internal pointer to it that every
  constructor overwrites and no destructor clears. The app created one per page,
  so closing a page left that pointer aimed at freed memory, and the next
  operation that used it walked a dead queue. There is now exactly one agent for
  the whole app, created once and never destroyed. The same fault is the likely
  cause of the occasional crashes after sending or when marking all as read.
- Opening a message no longer asks the server for something it already has. The
  body getters fetch on their own when the plain-text part is not fully local,
  which for encrypted mail is always - the readable text sits inside the
  encrypted part. Every binding that read the body produced one pointless
  request, which then queued up behind sending. The body is read once now, and
  not at all for encrypted mail.

* Fri Aug 14 2026 harbour-sfmail contributors 0.6.9-1
- Blind copies stay blind. One encrypted message names every recipient key in the
  clear (one packet per key in OpenPGP, one RecipientInfo per certificate in
  S/MIME), so anyone receiving it could read the whole list - a blind copy was
  blind in the headers only. Encrypted mail is now sent as one message per
  audience: the open recipients get theirs, every blind copy gets its own,
  encrypted only to the keys that belong in it.
- Blind copies were not encrypted to at all before this. The composer resolved
  keys for To and Cc only, so a blind recipient received a message encrypted to
  everyone but them and could not open it. S/MIME was never affected.
- The subject is no longer sent in the clear. Encrypted mail carries the real
  subject inside the encrypted part as a protected header and shows "..."
  outside, as other clients do. Clients without support for protected headers
  show "..." and reply with "Re: ...", and server-side search sees only the
  placeholder.
- The recipients travel inside the encryption as well, so a blind copy can still
  see whom the message was addressed to. The reader prefers those values over the
  visible headers - showing the outer To of a blind copy would claim its own
  recipient had been addressed.
- The encryption info now says which recipient key is listed in To/Cc, which is
  the sender's own, and which stands in no header at all.
- Inline PGP refuses a blind copy instead of pretending it can hide one: one
  armoured block in one message cannot serve separate audiences.

* Thu Aug 13 2026 harbour-sfmail contributors 0.6.1-1
- Encrypted mail is sent as encrypted mail again. QMF re-derives a MIME part's
  Content-Type from the file extension while parsing, and ".asc" is ambiguous in
  the shared MIME database - text/plain outranks the PGP types. The ciphertext
  part therefore left the device declared as text, which content filters score as
  an obfuscated payload; one provider answered 554. The part no longer carries a
  filename, so nothing can be re-guessed and application/octet-stream stands.
- Messages stuck in the outbox can be sent again, by hand from the outbox menu and
  automatically after 1, 2, 5, 10, 15, 30, 45 and 60 minutes. A permanent refusal
  (SMTP 5xx) schedules no retry - it would not help and only burdens the server.
- S/MIME picks its own certificate instead of handing gpgsm an address. With
  several certificates on one address gpgsm refused to choose at all; now the app
  chooses - an explicit preference first, otherwise the newest valid one that can
  encrypt - and passes the fingerprint. The preference is set per address in the
  certificate page.
- MIME boundaries are random instead of derived from message size and recipient
  count, and the User-Agent header is gone.

* Thu Aug 13 2026 harbour-sfmail contributors 0.5.5-1
- S/MIME works again on aarch64. Rebuilding the GnuPG stack in 0.5.4 replaced the
  staged tree wholesale and dropped three files it does not build itself: the
  bundled openssl, its legacy provider and pinentry. gpgsm was still present, but
  S/MIME also needs a runnable openssl, so it reported itself unavailable. The
  three now live in stack/extras/ as versioned inputs, build-stack.sh installs
  them, and a manifest check fails the build if any required file is missing.
  PGP was never affected, and armv7hl carries no openssl by design.

* Thu Aug 13 2026 harbour-sfmail contributors 0.5.4-1
- The bundled GnuPG stack was rebuilt so it no longer carries build paths. Its
  binaries had an absolute staging directory in RUNPATH and compile paths in
  their debug info, which 0.5.0 and 0.5.1 shipped. build-stack.sh now stops
  libtool from hardcoding the staging path, strips libexec/ as well as bin/ and
  the libraries, drops the bundled info/man/doc, and refuses to continue if a
  build path survives into a staged file.

* Thu Aug 13 2026 harbour-sfmail contributors 0.5.3-1
- Minimising the app now aborts a running delete countdown outright. 0.5.2 only
  suppressed the delete if the countdown expired while the app was away, so
  going out and coming back inside the four seconds still deleted.

* Thu Aug 13 2026 harbour-sfmail contributors 0.5.2-1
- Cancelling a delete now cancels it. The countdown lived inside the message
  row, and Silica runs such a timer when its row is destroyed - deleting one
  message rebuilt the list and fired the neighbour's still-running countdown,
  including one the user had tapped to cancel. Deleting runs off a page-level
  timer now, and leaving the page aborts instead of deleting.
- Messages can be moved between folders, in every folder rather than only in
  Trash: from a message's context menu, from the reader, and for a whole
  selection at once. Until now a message could be deleted but not put back.
