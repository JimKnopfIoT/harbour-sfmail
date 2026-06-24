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
sb2 -t "$TARGET" make -j4
sb2 -t "$TARGET" make install DESTDIR="$STAGE"
EOF

  "$CHROOT" bash -c "cd '$WORK/$dir' && bash _xbuild.sh"
  # Drop libtool archives: their absolute (device) paths break libtool-to-libtool
  # linking of later components during cross staging. Linking uses -L/.pc instead.
  find "$STAGE" -name '*.la' -delete
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
    --disable-gpg-test --enable-languages=cpp; }

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
