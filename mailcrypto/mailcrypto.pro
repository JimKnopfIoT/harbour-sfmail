TEMPLATE = lib
CONFIG += plugin c++17 link_pkgconfig
QT += qml network sql
QT -= gui
TARGET = sfmailgpg

# QMF (libqmfclient) for the PGP/MIME send path (multipart/encrypted).
PKGCONFIG += QmfClient

uri = SFMail.Gpg

# Keep absolute build paths (developer home dir / name) out of the shipped
# binary — important when redistributing the app.
QMAKE_CXXFLAGS += -ffile-prefix-map=$$absolute_path($$PWD/..)=.

SOURCES += \
    GpgEngine.cpp \
    SmimeEngine.cpp \
    plugin.cpp \
    qmf_abi_compat.cpp

HEADERS += \
    GpgEngine.h \
    SmimeEngine.h

# install as a QML extension plugin under the import path
installPath = $$[QT_INSTALL_QML]/$$replace(uri, \\., /)
target.path = $$installPath

qmldir.files = qmldir
qmldir.path = $$installPath

INSTALLS += target qmldir
