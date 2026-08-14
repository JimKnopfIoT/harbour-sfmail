# Third-party notices

`harbour-sfmail` is licensed GPL-3.0-or-later. It builds on and/or bundles the
third-party components below.

## Bundled (redistributed in the RPM)

The app ships a self-contained, maintained GnuPG 2.5 stack under
`/usr/share/harbour-sfmail/gpg/`. These are **unmodified upstream releases**,
compiled for the target. The exact source tarballs they were built from are
included in this repository under [`stack/src/`](stack/src/) (this is the
"corresponding source" required by the GPL/LGPL); see
[`stack/build-stack.sh`](stack/build-stack.sh) for how they are built.

| Component | Version | License | Upstream |
|-----------|---------|---------|----------|
| GnuPG (gpg, gpg-agent, gpgsm) | 2.5.21 | GPL-3.0-or-later | https://gnupg.org/ |
| Libgcrypt | 1.12.2 | LGPL-2.1-or-later | https://gnupg.org/software/libgcrypt/ |
| libgpg-error | 1.61 | LGPL-2.1-or-later / GPL-2.0-or-later | https://gnupg.org/software/libgpg-error/ |
| libassuan (two runtimes side by side) | 3.0.2 + 2.5.7 | LGPL-2.1-or-later | https://gnupg.org/software/libassuan/ |
| libksba | 1.8.0 | GPL-3.0-or-later / LGPL-3.0-or-later | https://gnupg.org/software/libksba/ |
| nPth | 1.8 | LGPL-2.1-or-later | https://gnupg.org/software/npth/ |
| GPGME (+ GpgME++) | 1.18.0 | LGPL-2.1-or-later (lib) | https://gnupg.org/software/gpgme/ |
| QGpgME (Qt binding, from the GPGME tarball) | 1.18.0 | GPL-2.0-or-later | https://gnupg.org/software/gpgme/ |
| OpenSSL (`bin/openssl`, legacy provider; aarch64 only) | 3.5.6 | Apache-2.0 | https://openssl.org/ |
| pinentry (aarch64 only, prebuilt) | see note | GPL-2.0-or-later | https://gnupg.org/software/pinentry/ |

`gpg-agent` runs with loopback pinentry only, so the bundled `pinentry` binary is
not on any code path the app uses; it ships for stack completeness (see
[`stack/extras/README.md`](stack/extras/README.md) for its provenance). Both
libassuan runtimes are intentional: `.so.9` serves GnuPG 2.5 (API 3), `.so.0`
serves GPGME 1.18 (API 2).

dirmngr and scdaemon are deliberately not built (no TLS backend / no card
support); keyserver lookups use the app's own HTTPS code instead.

The bundled GnuPG also ships its own standard data file
`share/gnupg/distsigkey.gpg` (the GnuPG release-signing public keys) — GnuPG's
own public file, part of every GnuPG installation.

Full license texts ship inside each upstream tarball (`COPYING`,
`COPYING.LGPL21`, `COPYING.LGPL3`, …) under `stack/src/`.

## Runtime dependencies (NOT bundled — provided by the OS)

These are used through their public APIs; no source from them is copied into
this project.

| Component | License | Notes |
|-----------|---------|-------|
| Qt 5 | LGPL-3.0 / GPL | Qt framework |
| Sailfish Silica | proprietary (Jolla) | SDK UI toolkit, present on device |
| QMF / libqmfclient (Qt Messaging Framework) | LGPL-2.1 | mail store / send, dynamically linked |
| nemo-qml-plugin-email (`Nemo.Email`) | BSD-3-Clause | accounts, folders, messages QML API |

> The stock Sailfish mail app uses the same `Nemo.Email` / QMF building blocks.
> harbour-sfmail's UI and PGP integration are original; no code from the stock
> mail app was copied.
