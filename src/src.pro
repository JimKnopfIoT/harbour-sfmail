TARGET = harbour-sfmail

QT += quick qml gui
CONFIG += sailfishapp sailfishapp_i18n

# Bilingual: English is the source (all qsTr). German is shipped as a .qm and
# auto-loaded by SailfishApp when the system language is German; otherwise English.
TRANSLATIONS += translations/harbour-sfmail-de.ts
# lupdate must see ALL qml (the QML_FILES list below is only a partial subset; the
# actual install uses qml/*). List every qml dir so no string is missed.
lupdate_only {
    SOURCES += qml/*.qml qml/pages/*.qml qml/cover/*.qml
}

# Keep absolute build paths (developer home dir / name) out of the shipped binary.
QMAKE_CXXFLAGS += -ffile-prefix-map=$$absolute_path($$PWD/..)=.

SOURCES += src/main.cpp
HEADERS += src/logcontrol.h

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
