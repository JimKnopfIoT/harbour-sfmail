TEMPLATE = subdirs
# Mail-App (harbour-sfmail) + schlankes gpg2-Wrapper-Plugin (SFMail.Gpg) für
# Key-Verwaltung und Inline-PGP. Kein gebündelter GnuPG-Stack — wir nutzen das
# System-gpg2 auf ~/.gnupg (derselbe Keyring wie der native QMF-Krypto-Pfad).
SUBDIRS = mailcrypto src
CONFIG += ordered
src.depends = mailcrypto

# Extended search (combinable filters, several accounts) as a plugin of its
# own: `qmake CONFIG+=sfmail_search`. The spec sets it unless built with
# `--without search`. The app runs unchanged without it; the search page offers
# the extended search only when the plugin is installed.
sfmail_search {
    SUBDIRS += mailsearch
}
