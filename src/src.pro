TARGET = harbour-sfmail

# dbus: we serve com.jolla.email.ui so that a tap on a new-mail notification
# opens SF-Mail instead of the stock client (see src/emailui.h).
QT += quick qml gui dbus
CONFIG += sailfishapp sailfishapp_i18n

# Bilingual: English is the source (all qsTr). German is shipped as a .qm and
# auto-loaded by SailfishApp when the system language is German; otherwise English.
# English is the source language; these files carry the translations. The app
# loads the one matching the device language and falls back to the source
# strings where there is none (see main.cpp).
TRANSLATIONS += \
    translations/harbour-sfmail-ar.ts \
    translations/harbour-sfmail-bg.ts \
    translations/harbour-sfmail-cs.ts \
    translations/harbour-sfmail-da.ts \
    translations/harbour-sfmail-de.ts \
    translations/harbour-sfmail-el.ts \
    translations/harbour-sfmail-en.ts \
    translations/harbour-sfmail-es.ts \
    translations/harbour-sfmail-et.ts \
    translations/harbour-sfmail-fa.ts \
    translations/harbour-sfmail-fi.ts \
    translations/harbour-sfmail-fr.ts \
    translations/harbour-sfmail-ga.ts \
    translations/harbour-sfmail-hi.ts \
    translations/harbour-sfmail-hr.ts \
    translations/harbour-sfmail-hu.ts \
    translations/harbour-sfmail-is.ts \
    translations/harbour-sfmail-it.ts \
    translations/harbour-sfmail-ja.ts \
    translations/harbour-sfmail-lt.ts \
    translations/harbour-sfmail-lv.ts \
    translations/harbour-sfmail-mt.ts \
    translations/harbour-sfmail-nb.ts \
    translations/harbour-sfmail-nl.ts \
    translations/harbour-sfmail-pl.ts \
    translations/harbour-sfmail-pt.ts \
    translations/harbour-sfmail-ro.ts \
    translations/harbour-sfmail-ru.ts \
    translations/harbour-sfmail-sk.ts \
    translations/harbour-sfmail-sl.ts \
    translations/harbour-sfmail-sv.ts \
    translations/harbour-sfmail-zh_CN.ts
# lupdate must see ALL qml (the QML_FILES list below is only a partial subset; the
# actual install uses qml/*). List every qml dir so no string is missed.
lupdate_only {
    SOURCES += qml/*.qml qml/pages/*.qml qml/cover/*.qml
}

# Keep absolute build paths (developer home dir / name) out of the shipped binary.
QMAKE_CXXFLAGS += -ffile-prefix-map=$$absolute_path($$PWD/..)=.

# Export symbols of the main binary so the crash-catcher's backtrace resolves our
# own function names (not just raw addresses). backtrace() also needs this.
QMAKE_LFLAGS += -rdynamic

SOURCES += src/main.cpp src/emailui.cpp
HEADERS += src/logcontrol.h src/emailui.h

QML_FILES = \
    qml/harbour-sfmail.qml \
    qml/pages/MailAccountsPage.qml \
    qml/pages/MessageListPage.qml \
    qml/pages/MessagePage.qml \
    qml/pages/ComposerPage.qml \
    qml/pages/KeysPage.qml \
    qml/pages/KeyTextPage.qml \
    qml/pages/SmimeCertsPage.qml \
    qml/pages/ContactPickerPage.qml \
    qml/pages/KeyImportDialog.qml \
    qml/pages/GenerateIdentityDialog.qml \
    qml/pages/ConfirmDialog.qml \
    qml/pages/PassphraseDialog.qml \
    qml/cover/CoverPage.qml

OTHER_FILES += $$QML_FILES harbour-sfmail.desktop

SAILFISHAPP_ICONS = 86x86 108x108 128x128 172x172

target.path = /usr/bin
INSTALLS += target

qml.path = /usr/share/$$TARGET/qml
qml.files = qml/*
INSTALLS += qml

desktop.path = /usr/share/applications
desktop.files = harbour-sfmail.desktop
INSTALLS += desktop
