# Prebuilt extras that build-stack.sh does not build

The GnuPG stack in `build-stack.sh` is built from source. These two files are
not: they are the operating system's own OpenSSL 3.5.6 build, copied here
because the sandbox hides other applications' files. The legacy provider is
byte-identical with the one in the 5.1 device image; that is also why the
aarch64 package requires Sailfish OS 5.1 or newer.

* `bin/openssl` — S/MIME needs a runnable openssl inside the sandbox; firejail's
  `private-bin` hides the system one. `SmimeEngine` shells out to it for .p12
  repacking and `signWithChain`.
* `lib/ossl-modules/legacy.so` — OpenSSL 3.x legacy provider, required to read
  .p12 files as written by other platforms and CA services.

Only aarch64: armv7hl never carried openssl, which is why `SmimeEngine` reports
S/MIME as unavailable there by design.

**Why this directory exists.** A rebuild of the stack replaces the staging tree
wholesale. On 2026-08-13 that silently dropped these files, and S/MIME
broke with "gpgsm not available" — gpgsm was present, but the availability check
also requires a runnable openssl. They are copied in by `build-stack.sh` now, and
the manifest check at the end of a full build fails if any of them is missing.
