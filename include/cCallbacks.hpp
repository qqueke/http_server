#ifndef C_CALLBACKS_HPP
#define C_CALLBACKS_HPP
#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"

void ClientSend(_In_ HQUIC Connection);

// The clients's callback for stream events from MsQuic.

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event);

// The clients's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ClientConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event);

void RunClient(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[]);

#endif
