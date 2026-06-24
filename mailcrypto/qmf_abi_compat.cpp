// QMF ABI shim.
//
// We build this plugin against the SailfishOS 5.0.0.62 SDK, but it runs on the
// device's SFOS 5.1 libQmfClient. Between those, libQmfClient stopped EXPORTING
// a couple of weak, out-of-line template destructors that the 5.0 headers
// reference. The result is a runtime "undefined symbol" abort the moment a
// QMailMessage is destroyed in this plugin (the PGP/MIME send path) — i.e. right
// after a successful send. The two missing symbols are:
//   QPrivatelyImplemented<QMailMessagePartContainerPrivate>::~QPrivatelyImplemented()
//   QPrivatelyImplemented<QMailMessageMetaDataPrivate>::~QPrivatelyImplemented()
// and, transitively, the matching QPrivateImplementationPointer<…> destructors.
//
// We provide local copies here. Both impl types derive DIRECTLY from
// QPrivateImplementationBase (offset 0), whose deref() self-deletes the impl via
// a type-erased delete_function — so we never need the impl's complete type:
// a reinterpret_cast to the base is valid and sufficient. QPrivatelyImplemented's
// own destructor body is empty; the member QPrivateImplementationPointer cleans
// up the shared impl.

#include <qprivateimplementation.h>

// Incomplete is fine — only used as template arguments + cast to the common base.
class QMailMessagePartContainerPrivate;
class QMailMessageMetaDataPrivate;

template<>
QPrivateImplementationPointer<QMailMessagePartContainerPrivate>::~QPrivateImplementationPointer()
{ if (d) reinterpret_cast<QPrivateImplementationBase*>(d)->deref(); }

template<>
QPrivatelyImplemented<QMailMessagePartContainerPrivate>::~QPrivatelyImplemented() {}

template<>
QPrivateImplementationPointer<QMailMessageMetaDataPrivate>::~QPrivateImplementationPointer()
{ if (d) reinterpret_cast<QPrivateImplementationBase*>(d)->deref(); }

template<>
QPrivatelyImplemented<QMailMessageMetaDataPrivate>::~QPrivatelyImplemented() {}
