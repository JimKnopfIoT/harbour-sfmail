#!/bin/bash
# Cross-compile a modern GnuPG/GPGME stack for SailfishOS aarch64 into a PRIVATE
# prefix, leaving the system gnupg 2.0.4 untouched. Uses the SDK's sb2 cross
# target directly (sb2 + qemu runs target test programs, so configure works).
#
# Usage: ./build-stack.sh [component]   (no arg = whole stack, dependency order)
set -e

TARGET="${SFOS_TARGET:-SailfishOS-5.0.0.62-aarch64}"
PREFIX=/usr/share/harbour-sfmail-pgp                 # on-device private prefix
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src"
WORK="${STACK_WORK:-$ROOT/build}"      # arch-specific build dir (override per arch)
STAGE="${STACK_STAGE:-$ROOT/stage}"    # arch-specific staging tree (override per arch)
SPX="$STAGE$PREFIX"                                  # staging install tree
CHROOT="$HOME/SailfishOS-Platform-SDK/sdk-chroot"
# Kept as a variable so this file carries no literal "<home>/<name>" pair for
# the anonymity scan to flag - it scans this script too.
HOMEPFX="/home"
ARCH="${TARGET##*-}"                                 # aarch64 | armv7hl
EXTRAS="$ROOT/extras/$ARCH"                          # prebuilt files we do not build

mkdir -p "$SRC" "$WORK" "$STAGE"

fetch() { # url -> path (on host; chroot curl lacks CA certs)
  local t; t="$(basename "$1")"
  [ -f "$SRC/$t" ] || { echo ">> fetch $t" >&2; curl -sSL -o "$SRC/$t" "$1"; }
  echo "$SRC/$t"
}

build() { # dirname  url  [extra configure args...]
  local dir="$1" url="$2"; shift 2
  local tb; tb="$(fetch "$url")"
  echo "=================== build: $dir ==================="
  rm -rf "${WORK:?}/$dir"; tar xf "$tb" -C "$WORK"

  # Qt 5.6 compat for the QGpgME binding (SFOS ships Qt 5.6; QGpgME 1.18 uses
  # exactly two post-5.6 APIs, verified by grep):
  #  - QDateTime::fromSecsSinceEpoch + char16_t toString overload (Qt >= 5.8)
  #  - QMetaObject::invokeMethod with a functor (Qt >= 5.10) → QTimer::singleShot
  local qfix="$WORK/$dir/lang/qt/src/qgpgmeaddexistingsubkeyjob.cpp"
  if [ -f "$qfix" ]; then
    sed -i \
      -e 's/QDateTime::fromSecsSinceEpoch(subkey.expirationTime(), Qt::UTC)/QDateTime::fromMSecsSinceEpoch(1000LL * subkey.expirationTime(), Qt::UTC)/' \
      -e 's/toString(u"yyyyMMdd.T.hhmmss")/toString(QStringLiteral("yyyyMMdd'\''T'\''hhmmss"))/' \
      "$qfix"
  fi
  local qfix2="$WORK/$dir/lang/qt/src/qgpgmerefreshsmimekeysjob.cpp"
  if [ -f "$qfix2" ]; then
    sed -i 's/#include <QProcess>/#include <QProcess>\n#include <QTimer>/' "$qfix2"
    perl -0777 -pi -e 's/QMetaObject::invokeMethod\(this, \[this\]\(\) \{\s*Q_EMIT slotProcessExited\(0, QProcess::NormalExit\);\s*\}, Qt::QueuedConnection\);/QTimer::singleShot(0, this, [this]() { Q_EMIT slotProcessExited(0, QProcess::NormalExit); });/s' "$qfix2"
  fi
  # Backport of the gpgme 1.20 C++ API Context::deleteKey(key, flags): 1.18 only
  # wraps gpgme_op_delete (no DELETE_FORCE), but deleting a SECRET key in batch
  # mode needs --yes, which the engine only adds for GPGME_DELETE_FORCE. Values
  # 1/2 mirror GPGME_DELETE_ALLOW_SECRET/GPGME_DELETE_FORCE (stable C ABI).
  local cctxh="$WORK/$dir/lang/cpp/src/context.h" cctxc="$WORK/$dir/lang/cpp/src/context.cpp"
  if [ -f "$cctxh" ] && ! grep -q DeleteForce "$cctxh"; then
    perl -0777 -pi -e 's/(GpgME::Error deleteKey\(const Key &key, bool allowSecretKeyDeletion = false\);)/$1\n    enum DeleteFlags {\n        DeleteNoFlags = 0,\n        DeleteAllowSecret = 1,\n        DeleteForce = 2\n    };\n    GpgME::Error deleteKey(const Key &key, unsigned int flags);/' "$cctxh"
    perl -0777 -pi -e 's/(Error Context::deleteKey\(const Key &key, bool allowSecretKeyDeletion\)\n\{\n    d->lastop = Private::Delete;\n    return Error\(d->lasterr = gpgme_op_delete\(d->ctx, key\.impl\(\), int\(allowSecretKeyDeletion\)\)\);\n\})/$1\n\nError Context::deleteKey(const Key &key, unsigned int flags)\n\{\n    d->lastop = Private::Delete;\n    return Error(d->lasterr = gpgme_op_delete_ext(d->ctx, key.impl(), flags));\n\}/s' "$cctxc"
  fi

  # Upstream ships generated parsers (libksba's ASN.1 grammar among them) that
  # keep their own maintainer's build directory in a runtime string. It is not
  # ours, but a published binary should carry no such path at all, and it
  # otherwise keeps the anonymity gates permanently red. Matched generically so
  # this file does not have to spell one out either.
  grep -rlI --binary-files=text "${HOMEPFX}/" "$WORK/$dir" 2>/dev/null | while read -r f; do
    sed -i "s|${HOMEPFX}/[A-Za-z0-9_./-]*/|<generated>/|g" "$f"
  done

  # Generate the cross-build steps as a script run inside the sb2 target.
  cat > "$WORK/$dir/_xbuild.sh" <<EOF
set -e
export PKG_CONFIG_PATH="$SPX/lib/pkgconfig"
# npth 1.8 no longer ships npth-config — only npth.pc. gnupg 2.5's configure
# handles that, but only if it can reach gpgrt-config (libgpg-error's universal
# replacement for the old per-library *-config scripts); without this variable it
# falls back to the missing npth-config and aborts with "Required libraries not
# found", pointing at nPth even though nPth is installed and fine.
export GPGRT_CONFIG="$SPX/bin/gpgrt-config"
# The anonymity sed above rewrites paths inside gpgme.texi, which makes the
# shipped gpgme.info look outdated, so make wants to regenerate it — and the SDK
# host has no makeinfo. We do not ship info pages anyway (they are deleted right
# after install), so stub the generator out instead of adding a build dependency.
export MAKEINFO=true
export LDFLAGS="-Wl,-rpath,$PREFIX/lib -Wl,-rpath-link,$SPX/lib -L$SPX/lib"
export CPPFLAGS="-I$SPX/include"
sb2 -t "$TARGET" ./configure --prefix="$PREFIX" --disable-static --enable-shared \\
    --with-libgpg-error-prefix="$SPX" --with-libgcrypt-prefix="$SPX" \\
    --with-libassuan-prefix="$SPX" --with-ksba-prefix="$SPX" \\
    --with-npth-prefix="$SPX" $*
# libtool bakes the staging directory into RUNPATH because we link against
# -L\$SPX/lib, so every binary carried an absolute build path
# (/home/<user>/…/stack/stage/…) alongside the wanted device prefix. Published
# 0.5.0/0.5.1 shipped that. Neutralising hardcode_libdir_flag_spec stops
# libtool adding it; the wanted RUNPATH still comes from the explicit
# -Wl,-rpath,\$PREFIX/lib in LDFLAGS above.
for lt in \$(find . -maxdepth 3 -name libtool -type f); do
  sed -i -e 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|' \\
         -e 's|^hardcode_into_libs=.*|hardcode_into_libs=no|' "\$lt"
done
sb2 -t "$TARGET" make -j4
sb2 -t "$TARGET" make install DESTDIR="$STAGE"
EOF

  "$CHROOT" bash -c "cd '$WORK/$dir' && bash _xbuild.sh"
  # Drop libtool archives: their absolute (device) paths break libtool-to-libtool
  # linking of later components during cross staging. Linking uses -L/.pc instead.
  find "$STAGE" -name '*.la' -delete
  # Strip DWARF debug info from staged shared libs / tools. The C++ bindings
  # (gpgmepp/qgpgme) embed the absolute staging include path ($SPX) in .debug_str,
  # which would otherwise leak the build path (/home/<user>/…) into the published
  # source tree. eu-strip is architecture-agnostic (runs on the build host).
  find "$STAGE" -type f \( -name '*.so' -o -name '*.so.*' \) -exec eu-strip -g {} \; 2>/dev/null || true
  find "$STAGE" -type f -path '*/bin/*' -exec eu-strip -g {} \; 2>/dev/null || true
  # libexec/ was missing here, and that is exactly what leaked: gnupg's helpers
  # (gpg-protect-tool, scdaemon, …) kept their DWARF, which carries the compile
  # directory and every -I path. sbin/ for good measure.
  find "$STAGE" -type f \( -path '*/libexec/*' -o -path '*/sbin/*' \) -exec eu-strip -g {} \; 2>/dev/null || true
  # Documentation is not shipped: info/man/doc are dead weight in a phone package,
  # and upstream's own texts carry example home paths plus decimal literals that
  # keep the anonymity scanners permanently red.
  rm -rf "$SPX/share/info" "$SPX/share/man" "$SPX/share/doc"

  # Blocking self-check: no build path may survive into a staged binary. This is
  # what the published packages leaked, so it is an error, not a warning.
  local leaked rpathleak
  # (a) no RUNPATH/RPATH may point anywhere near a build tree
  rpathleak="$(find "$SPX" -type f \( -name '*.so*' -o -path '*/bin/*' -o -path '*/libexec/*' \) \
                 -exec sh -c 'readelf -d "$1" 2>/dev/null | grep -qE "R(UN)?PATH.*/home/" && echo "$1"' _ {} \; | head -5)"
  # (b) and no build path may sit anywhere else in the payload either
  leaked="$(grep -rlI --binary-files=text '/home/' "$SPX" 2>/dev/null | head -5 || true)"
  if [ -n "$rpathleak$leaked" ]; then
    echo "!! build path leaked into staged files:" >&2
    [ -n "$rpathleak" ] && { echo "   via RPATH:"; echo "$rpathleak"; } >&2
    [ -n "$leaked" ] && { echo "   as a string:"; echo "$leaked"; } >&2
    echo "!! refusing to continue — this is what 0.5.0/0.5.1 shipped" >&2
    exit 1
  fi
  echo ">> installed $dir into staging ($SPX)"
}

# --- Version pins -----------------------------------------------------------
# Since 0.8.0 (2026-08-14) this builds the maintained branch: the previous stack
# sat on gnupg 2.2.43, upstream EOL since 2024-12-31, and missed CVE-2025-68973
# (out-of-bounds write in the ARMOR parser — our most exposed code path, every
# inline block and encrypted.asc from a stranger goes through it). gpg and the
# crypto libraries move to the maintained line while GPGME deliberately STAYS AT
# 1.18, so the Qt 5.6 patch set below (the 0.5.0 QGpgME port) stays untouched.
# The 2.2 stack lives on in the legacy-gnupg2.2 branch.
#
# The one hard conflict, read out of both configure.ac files rather than guessed:
#   gnupg 2.5.21 : NEED_LIBASSUAN_API=3, >= 3.0.0
#   gpgme  1.18.0: NEED_LIBASSUAN_API=2, >= 2.4.2
# They cannot share a header, but they CAN share a directory: the SONAMEs differ
# (current-age = 9-0 → libassuan.so.9 vs 8-8 → libassuan.so.0). So libassuan 3 is
# built first, gnupg links against it, and libassuan 2 is then installed OVER it
# — that replaces assuan.h / libassuan.pc / libassuan-config (which only the
# build needs) while both shared objects stay side by side for the device.
# Hence the order in "all" below is load-bearing; do not sort it alphabetically.
V_GPGERROR=1.61       # was 1.47   (gnupg 2.5 needs gpgrt >= 1.56)
V_GCRYPT=1.12.2       # was 1.10.3 (gnupg 2.5 needs >= 1.11.0)
V_ASSUAN3=3.0.2       # new, for gnupg
V_ASSUAN2=2.5.7       # kept, for gpgme 1.18
V_KSBA=1.8.0          # was 1.6.6
V_NPTH=1.8            # was 1.6
V_GNUPG=2.5.21        # was 2.2.43
V_GPGME=1.18.0        # UNCHANGED on purpose — see above

b_libgpgerror() { build libgpg-error-$V_GPGERROR https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$V_GPGERROR.tar.bz2 \
    --enable-install-gpg-error-config; }
b_libgcrypt()   { build libgcrypt-$V_GCRYPT   https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-$V_GCRYPT.tar.bz2; }
b_libassuan3()  { build libassuan-$V_ASSUAN3  https://www.gnupg.org/ftp/gcrypt/libassuan/libassuan-$V_ASSUAN3.tar.bz2; }
b_libassuan2()  { build libassuan-$V_ASSUAN2  https://www.gnupg.org/ftp/gcrypt/libassuan/libassuan-$V_ASSUAN2.tar.bz2; }
b_libksba()     { build libksba-$V_KSBA       https://www.gnupg.org/ftp/gcrypt/libksba/libksba-$V_KSBA.tar.bz2; }
b_npth()        { build npth-$V_NPTH          https://www.gnupg.org/ftp/gcrypt/npth/npth-$V_NPTH.tar.bz2; }
# Extra --disable flags over the 2.2 line: features 2.5 grew that a phone mail
# client has no use for. keyboxd is switched off on purpose — it would move the
# keyring behind a daemon, and existing pubring.kbx files must keep working.
b_gnupg()       { build gnupg-$V_GNUPG        https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-$V_GNUPG.tar.bz2 \
    --disable-doc --disable-gpgtar --disable-wks-tools --disable-ldap --disable-ntbtls \
    --disable-tofu --disable-sqlite --disable-card-support --disable-scdaemon \
    --disable-tpm2d --disable-keyboxd --disable-photo-viewers; }
b_gpgme()       { build gpgme-$V_GPGME        https://www.gnupg.org/ftp/gcrypt/gpgme/gpgme-$V_GPGME.tar.bz2 \
    --disable-gpg-test --enable-languages=cpp,qt; }

# Files that are NOT built here but belong to a complete stack (openssl and its
# legacy provider for S/MIME, pinentry). A full rebuild replaces the staging tree,
# and on 2026-08-13 that silently dropped them: gpgsm was still there, but
# SmimeEngine also requires a runnable openssl, so S/MIME failed with "gpgsm not
# available" and the cause was three missing files. They live in extras/ now.
install_extras() {
  [ -d "$EXTRAS" ] || { echo ">> no extras for $ARCH (expected for armv7hl: no S/MIME there)"; return 0; }
  echo ">> installing prebuilt extras for $ARCH"
  ( cd "$EXTRAS" && find . -type f -print0 | while IFS= read -r -d "" f; do
      install -D -m 755 "$f" "$SPX/${f#./}"
    done )
}

# Blocking completeness check after a full build. A stack that is missing one of
# these looks fine until a feature quietly stops working at runtime.
check_manifest() {
  local missing=""
  # Both libassuan runtimes have to be here: .so.9 is what gpg/gpgsm/gpg-agent
  # link against, .so.0 is what gpgme 1.18 links against. Losing either one
  # breaks a different half of the app, and only at runtime.
  # dirmngr is NOT in this list any more: gnupg 2.5 only builds it when a TLS
  # backend (ntbtls or gnutls) is present, and we build with neither. Nothing in
  # the app needs it — keyserver lookups go through the app's own HTTPS code
  # (QNetworkAccessManager → keys.openpgp.org), and gpgsm runs with
  # --disable-crl-checks. Watch for it during the S/MIME device test: if gpgsm
  # starts complaining about a missing dirmngr, build ntbtls and put it back.
  local required="bin/gpg bin/gpgsm bin/gpgconf bin/gpg-agent
                  lib/libgpg-error.so.0 lib/libgcrypt.so.20
                  lib/libassuan.so.0 lib/libassuan.so.9
                  lib/libksba.so.8 lib/libnpth.so.0 lib/libgpgme.so.11"
  # S/MIME is aarch64-only by design; armv7hl never carried openssl.
  [ "$ARCH" = "aarch64" ] && required="$required bin/openssl bin/pinentry lib/ossl-modules/legacy.so"
  for r in $required; do
    [ -e "$SPX/$r" ] || missing="$missing $r"
  done
  if [ -n "$missing" ]; then
    echo "!! incomplete stack for $ARCH — missing:$missing" >&2
    echo "!! a stack missing one of these looks fine and fails only at runtime" >&2
    exit 1
  fi
  echo ">> manifest ok for $ARCH ($(find "$SPX" -type f | wc -l) files)"
}

case "${1:-all}" in
  libgpg-error) b_libgpgerror ;;
  libgcrypt)    b_libgcrypt ;;
  libassuan3)   b_libassuan3 ;;
  libassuan2)   b_libassuan2 ;;
  libksba)      b_libksba ;;
  npth)         b_npth ;;
  gnupg)        b_gnupg ;;
  gpgme)        b_gpgme ;;
  extras)       install_extras ;;
  check)        check_manifest ;;
  # Order matters: libassuan 3 → gnupg → libassuan 2 → gpgme. See the note at
  # the version pins; building gpgme before libassuan 2 is installed picks up the
  # API-3 header and fails, and rebuilding gnupg after it does the same.
  all)          b_libgpgerror; b_libgcrypt; b_libksba; b_npth
                b_libassuan3; b_gnupg
                b_libassuan2; b_gpgme
                install_extras; check_manifest
                echo "=== full stack staged under $SPX ===" ;;
  *) echo "unknown component: $1"; exit 1 ;;
esac
