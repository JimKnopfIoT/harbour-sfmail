// QMF ABI shim.
//
// We build this plugin against the SailfishOS 5.0.0.62 SDK, but it runs on the
// device's newer libQmfClient. That library does NOT export a couple of weak,
// out-of-line template destructors that the QMF headers reference, so a
// QMailMessage destroyed in this plugin (the PGP/MIME send path) would abort with
// an "undefined symbol". We therefore provide those destructors here.
//
// IMPORTANT (crash fix): the previous version defined them via
//   reinterpret_cast<QPrivateImplementationBase*>(d)->deref()
// which is WRONG. QMailMessage inherits BOTH QPrivatelyImplemented<…MetaDataPrivate>
// and QPrivatelyImplemented<…PartContainerPrivate>; QMF bridges those private
// impls through the QPrivateImplementationBase `self`/clone machinery, so the
// QPrivateImplementationBase subobject is NOT necessarily at offset 0 of what `d`
// points to. A reinterpret_cast skips the base-subobject adjustment, so deref()
// read `self`/`delete_function` from the wrong offsets and called a garbage
// function pointer — an intermittent SIGSEGV right after a successful send
// (confirmed by a core dump: crash inside this destructor, calling delete_function
// = 0x79_00000000, arg = the message status flags).
//
// The fix: include the private header so the COMPLETE impl types are known, then
// call d->deref() through the real type. The compiler now performs the correct
// derived→base pointer adjustment for each impl type. deref() itself decrements
// the shared refcount and, on reaching zero, invokes the type-erased
// delete_function — exactly Qt's own out-of-line destructor body.

#include <QmfClient/private/qmailmessage_p.h>

template<>
QPrivateImplementationPointer<QMailMessageMetaDataPrivate>::~QPrivateImplementationPointer()
{ if (d) d->deref(); }

template<>
QPrivatelyImplemented<QMailMessageMetaDataPrivate>::~QPrivatelyImplemented() {}

template<>
QPrivateImplementationPointer<QMailMessagePartContainerPrivate>::~QPrivateImplementationPointer()
{ if (d) d->deref(); }

template<>
QPrivatelyImplemented<QMailMessagePartContainerPrivate>::~QPrivatelyImplemented() {}
