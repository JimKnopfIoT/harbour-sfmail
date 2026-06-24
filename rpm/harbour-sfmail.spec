Name:       harbour-sfmail
Summary:    E-mail client with built-in OpenPGP for Sailfish OS
Version:    0.3.82
Release:    1
Group:      Applications/Productivity
License:    GPLv3+
URL:        https://github.com/
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
# Ship only what the app actually invokes at runtime (gpg, gpg-agent, gpgsm,
# dirmngr, gpgconf, openssl, pinentry, gpg-protect-tool) — a smaller RPM AND a
# smaller attack surface. Dropping share/locale also forces gpg/gpgsm to emit
# ENGLISH status text, which our stderr parsing relies on.
GPGDIR=%{buildroot}%{_datadir}/%{name}/gpg
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

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%{_datadir}/%{name}
%{_libdir}/qt5/qml/SFMail/Gpg
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.png
