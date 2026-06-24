#include <QQmlExtensionPlugin>
#include <QQmlEngine>
#include <QtQml>

#include "GpgEngine.h"
#include "SmimeEngine.h"

static QObject *gpgSingletonProvider(QQmlEngine *, QJSEngine *)
{
    return new GpgEngine;
}

static QObject *smimeSingletonProvider(QQmlEngine *, QJSEngine *)
{
    return new SmimeEngine;
}

class MailCryptoPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.qt-project.Qt.QQmlExtensionInterface")

public:
    void registerTypes(const char *uri) override
    {
        // import SFMail.Gpg 1.0  ->  singletons "Gpg" (OpenPGP) and "Smime" (S/MIME)
        qmlRegisterSingletonType<GpgEngine>(uri, 1, 0, "Gpg", gpgSingletonProvider);
        qmlRegisterSingletonType<SmimeEngine>(uri, 1, 0, "Smime", smimeSingletonProvider);
    }
};

#include "plugin.moc"
