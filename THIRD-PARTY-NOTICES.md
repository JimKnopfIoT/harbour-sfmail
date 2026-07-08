# Third-party notices

`harbour-sfmail` is licensed GPL-3.0-or-later. It builds on and/or bundles the
third-party components below.

## Bundled (redistributed in the RPM)

The app ships a self-contained GnuPG 2.2 stack under
`/usr/share/harbour-sfmail/gpg/`. These are **unmodified upstream releases**,
compiled for the target. The exact source tarballs they were built from are
included in this repository under [`stack/src/`](stack/src/) (this is the
"corresponding source" required by the GPL/LGPL); see
[`stack/build-stack.sh`](stack/build-stack.sh) for how they are built.

| Component | Version | License | Upstream |
|-----------|---------|---------|----------|
| GnuPG (gpg, gpg-agent, gpgsm, dirmngr, scdaemon, …) | 2.2.43 | GPL-3.0-or-later | https://gnupg.org/ |
| Libgcrypt | 1.10.3 | LGPL-2.1-or-later | https://gnupg.org/software/libgcrypt/ |
| libgpg-error | 1.47 | LGPL-2.1-or-later / GPL-2.0-or-later | https://gnupg.org/software/libgpg-error/ |
| libassuan | 2.5.7 | LGPL-2.1-or-later | https://gnupg.org/software/libassuan/ |
| libksba | 1.6.6 | GPL-3.0-or-later / LGPL-3.0-or-later | https://gnupg.org/software/libksba/ |
| nPth | 1.6 | LGPL-2.1-or-later | https://gnupg.org/software/npth/ |
| GPGME (+ gpgmepp) | 1.18.0 | LGPL-2.1-or-later (lib) | https://gnupg.org/software/gpgme/ |

The bundled GnuPG also ships its own standard data files
`share/gnupg/distsigkey.gpg` (the GnuPG release-signing public keys) and
`share/gnupg/sks-keyservers.netCA.pem` (keyserver pool CA). These are GnuPG's
own public files, part of every GnuPG installation.

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
