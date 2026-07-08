TEMPLATE = subdirs
# Mail-App (harbour-sfmail) + schlankes gpg2-Wrapper-Plugin (SFMail.Gpg) für
# Key-Verwaltung und Inline-PGP. Kein gebündelter GnuPG-Stack — wir nutzen das
# System-gpg2 auf ~/.gnupg (derselbe Keyring wie der native QMF-Krypto-Pfad).
SUBDIRS = mailcrypto src
CONFIG += ordered
src.depends = mailcrypto
