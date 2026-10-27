TEMPLATE = lib
CONFIG += plugin c++17 link_pkgconfig
QT += qml
QT -= gui

# Extended search: combinable filters over the mail store and, on request, the
# IMAP server. Metadata only — this plugin never decrypts and never writes
# message content anywhere; encrypted text stays as unsearchable as it is
# stored.
TARGET = sfmailsearch

PKGCONFIG += QmfClient
# Private headers for the shared ABI shim (see mailcrypto/qmf_abi_compat.cpp).
INCLUDEPATH += /usr/include/qt5/QmfClient/5.0.0

uri = SFMail.Search

# Keep absolute build paths out of the shipped binary.
QMAKE_CXXFLAGS += -ffile-prefix-map=$$absolute_path($$PWD/..)=.

SOURCES += \
    MailSearchModel.cpp \
    plugin.cpp

HEADERS += \
    MailSearchModel.h

# Loading QMailMessageMetaData pulls in the same template destructors the
# crypto plugin needs on newer devices; same shim, same feature test.
HAVE_QMF_PIMPL = $$system(grep -sl QPrivatelyImplemented /usr/include/qt5/QmfClient/qmailmessage.h)
!isEmpty(HAVE_QMF_PIMPL) {
    SOURCES += ../mailcrypto/qmf_abi_compat.cpp
} else {
    message("QMF without QPrivatelyImplemented — building WITHOUT qmf_abi_compat.cpp")
}

installPath = $$[QT_INSTALL_QML]/$$replace(uri, \\., /)
target.path = $$installPath

qmldir.files = qmldir
qmldir.path = $$installPath

INSTALLS += target qmldir
