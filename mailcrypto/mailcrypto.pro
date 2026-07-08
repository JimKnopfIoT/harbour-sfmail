TEMPLATE = lib
CONFIG += plugin c++17 link_pkgconfig
QT += qml network sql concurrent
QT -= gui

# GpgME++/QGpgME (C++/Qt bindings) from the bundled cross-built stack. Headers
# come from the stage tree matching the build target; at runtime the libraries
# are resolved through this plugin's DT_RPATH pointing into the app's own
# bundled gpg/lib (the stack libs carry classic DT_RPATH, so the loader also
# finds their inter-dependencies via our rpath — keep --disable-new-dtags so we
# emit DT_RPATH, not DT_RUNPATH).
equals(QT_ARCH, arm) {
    STACK_STAGE = $$PWD/../stack/stage-armv7hl
} else {
    STACK_STAGE = $$PWD/../stack/stage-aarch64
}
INCLUDEPATH += $$STACK_STAGE/usr/share/harbour-sfmail-pgp/include
# GPGME was cross-built with large-file support; on 32-bit ARM its header
# refuses to compile unless the consumer matches (off_t sizes must agree).
# No-op on aarch64 (off_t is 64-bit there anyway).
DEFINES += _FILE_OFFSET_BITS=64
LIBS += -L$$STACK_STAGE/usr/share/harbour-sfmail-pgp/lib -lqgpgme -lgpgmepp -lgpgme -lassuan -lgpg-error
QMAKE_LFLAGS += -Wl,--disable-new-dtags \
                -Wl,-rpath,/usr/share/harbour-sfmail/gpg/lib \
                -Wl,-rpath-link,$$STACK_STAGE/usr/share/harbour-sfmail-pgp/lib
TARGET = sfmailgpg

# QMF (libqmfclient) for the PGP/MIME send path (multipart/encrypted).
PKGCONFIG += QmfClient
# QMF private headers (for qmf_abi_compat.cpp — the impl destructors need the
# COMPLETE private impl types to navigate the base subobject correctly). Both the
# aarch64 (5.0.0.62) and armv7hl (4.6.0.13) sysroots ship them under .../5.0.0.
INCLUDEPATH += /usr/include/qt5/QmfClient/5.0.0

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
