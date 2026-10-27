#include <QQmlExtensionPlugin>
#include <QtQml>

#include "MailSearchModel.h"

class MailSearchPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.qt-project.Qt.QQmlExtensionInterface")

public:
    void registerTypes(const char *uri) override
    {
        // import SFMail.Search 1.0  ->  MailSearch (a list model of matches)
        qmlRegisterType<MailSearchModel>(uri, 1, 0, "MailSearch");
    }
};

#include "plugin.moc"
