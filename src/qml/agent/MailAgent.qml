pragma Singleton
import QtQuick 2.6
import Nemo.Email 0.1

// The ONE EmailAgent instance for the whole process.
//
// Why this has to exist: EmailAgent is registered with qmlRegisterType, so QML can
// instantiate it — and every constructor points the plugin's internal singleton at
// itself (emailagent.cpp: "m_instance = this"), while the destructor does NOT clear
// it. An EmailAgent declared inside a page that gets pushed and popped therefore
// leaves that pointer aimed at freed memory. EmailMessageListModel::
// deleteSelectedMessages() calls EmailAgent::instance()->deleteMessages()
// internally, so the next delete walks a dead action queue:
//
//   #0 EmailAgent::actionInQueueId(QSharedPointer<EmailAction>) const  <- SIGSEGV
//   #3 EmailAgent::deleteMessages(...)
//   #4 EmailMessageListModel::deleteSelectedMessages()
//
// Reproduced on device: open a mail, go back, select several mails, delete — the
// app dies at the end of the countdown and the mails are still there afterwards,
// because it never got as far as deleting them. Without opening a mail first it
// works, which is exactly the difference between "a page with an EmailAgent was
// destroyed" and "none was".
//
// A QML singleton is created once and lives until the engine shuts down, so the
// plugin's pointer stays valid for the whole runtime. The stock Jolla client does
// the same thing by convention: one EmailAgent in its root object, never destroyed.
EmailAgent { }
