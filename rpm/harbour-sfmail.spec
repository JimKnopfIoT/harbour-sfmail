# Keep the local machine name out of the RPM header (Build Host) — the
# released packages must not leak the build environment.
%global _buildhost reproducible-builder

Name:       harbour-sfmail
Summary:    E-mail client with built-in OpenPGP for Sailfish OS
Version:    0.6.1
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
%define stackstage stack/stage-armv7hl
%else
%define stackstage stack/stage-aarch64
%endif
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
Exec=/usr/bin/sailjail -p %{name}.desktop %{_bindir}/%{name}
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
Exec=/usr/bin/sailjail -p %{name}.desktop %{_bindir}/%{name}
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
