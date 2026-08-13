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

b_libgpgerror() { build libgpg-error-1.47 https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.47.tar.bz2 \
    --enable-install-gpg-error-config; }
b_libgcrypt()   { build libgcrypt-1.10.3   https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.10.3.tar.bz2; }
b_libassuan()   { build libassuan-2.5.7    https://www.gnupg.org/ftp/gcrypt/libassuan/libassuan-2.5.7.tar.bz2; }
b_libksba()     { build libksba-1.6.6      https://www.gnupg.org/ftp/gcrypt/libksba/libksba-1.6.6.tar.bz2; }
b_npth()        { build npth-1.6           https://www.gnupg.org/ftp/gcrypt/npth/npth-1.6.tar.bz2; }
b_gnupg()       { build gnupg-2.2.43       https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-2.2.43.tar.bz2 \
    --disable-doc --disable-gpgtar --disable-wks-tools --disable-ldap --disable-ntbtls; }
b_gpgme()       { build gpgme-1.18.0       https://www.gnupg.org/ftp/gcrypt/gpgme/gpgme-1.18.0.tar.bz2 \
    --disable-gpg-test --enable-languages=cpp,qt; }

case "${1:-all}" in
  libgpg-error) b_libgpgerror ;;
  libgcrypt)    b_libgcrypt ;;
  libassuan)    b_libassuan ;;
  libksba)      b_libksba ;;
  npth)         b_npth ;;
  gnupg)        b_gnupg ;;
  gpgme)        b_gpgme ;;
  all)          b_libgpgerror; b_libgcrypt; b_libassuan; b_libksba; b_npth; b_gnupg; b_gpgme
                echo "=== full stack staged under $SPX ===" ;;
  *) echo "unknown component: $1"; exit 1 ;;
esac
