# Prebuilt extras that build-stack.sh does not build

The GnuPG stack in `build-stack.sh` is built from source. These files are not:
they are prebuilt binaries that have travelled with the project, and no record
of how they were produced survives.

* `bin/openssl` — S/MIME needs a runnable openssl inside the sandbox; firejail's
  `private-bin` hides the system one. `SmimeEngine` shells out to it for .p12
  repacking and `signWithChain`.
* `lib/ossl-modules/legacy.so` — OpenSSL 3.x legacy provider, required to read
  .p12 files written by Windows and Volksverschlüsselung.
* `bin/pinentry` — gpg-agent's passphrase helper. The app sets
  `allow-loopback-pinentry`, so it is not on the critical path, but it belongs
  to a complete stack.

Only aarch64: armv7hl never carried openssl, which is why `SmimeEngine` reports
S/MIME as unavailable there by design.

**Why this directory exists.** A rebuild of the stack replaces the staging tree
wholesale. On 2026-08-13 that silently dropped these three files, and S/MIME
broke with "gpgsm not available" — gpgsm was present, but the availability check
also requires a runnable openssl. They are copied in by `build-stack.sh` now, and
the manifest check at the end of a full build fails if any of them is missing.
