#include "sCallbacks.hpp"
#include "utils.hpp"
#include "server.hpp"
#include <string>
// #include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"

// Allocates and sends some data over a QUIC stream.
void ServerSend(_In_ HQUIC Stream) {
  // Allocates and builds the buffer to send over the stream.

  std::string message("Hello!");

  void *SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + message.size());

  // void *SendBufferRaw = malloc(sizeof(QUIC_BUFFER) +SendBufferLength);
  if (SendBufferRaw == nullptr) {
    printf("SendBuffer allocation failed!\n");
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    return;
  }

  QUIC_BUFFER *SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
  SendBuffer->Buffer = (uint8_t *)SendBufferRaw + sizeof(QUIC_BUFFER);
  SendBuffer->Length = message.size();

  memcpy(SendBuffer->Buffer, message.c_str(), message.size());

  printf("[strm][%p] Sending data...\n", Stream);

  // Sends the buffer over the stream. Note the FIN flag is passed along with
  // the buffer. This indicates this is the last buffer on the stream and the
  // the stream is shut down (in the send direction) immediately after.
  QUIC_STATUS Status = 0;
  if (QUIC_FAILED(Status = MsQuic->StreamSend(
                      Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
    printf("StreamSend failed, 0x%x!\n", Status);
    free(SendBufferRaw);
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    return;
  }
}

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ServerStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);
  HTTPServer *server = (HTTPServer *)Context;

  switch (Event->Type) {
  case QUIC_STREAM_EVENT_SEND_COMPLETE:
    //
    // A previous StreamSend call has completed, and the context is being
    // returned back to the app.
    //

    free(Event->SEND_COMPLETE.ClientContext);
    printf("[strm][%p] Data sent\n", Stream);
    break;
  case QUIC_STREAM_EVENT_RECEIVE:

    // Data was received from the peer on the stream.

    printf("[strm][%p] Data received\n", Stream);

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

      // Print received data (assuming text)
      fwrite(buffer->Buffer, 1, buffer->Length, stdout);
      printf("\n");
    }
    printf("\n");

      server->PrintFromServer();
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    //
    // The peer gracefully shut down its send direction of the stream.
    //
    printf("[strm][%p] Peer shut down\n", Stream);
    ServerSend(Stream);
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    //
    // The peer aborted its send direction of the stream.
    //
    printf("[strm][%p] Peer aborted\n", Stream);
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    break;
  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
    //
    // Both directions of the stream have been shut down and MsQuic is done
    // with the stream. It can now be safely cleaned up.
    //
    printf("[strm][%p] All done\n", Stream);
    MsQuic->StreamClose(Stream);
    break;
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ServerConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);
  switch (Event->Type) {
  case QUIC_CONNECTION_EVENT_CONNECTED:

    // The handshake has completed for the connection.

    printf("[conn][%p] Connected\n", Connection);
    MsQuic->ConnectionSendResumptionTicket(
        Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:

    // The connection has been shut down by the transport. Generally, this
    // is the expected way for the connection to shut down with this
    // protocol, since we let idle timeout kill the connection.

    if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
        QUIC_STATUS_CONNECTION_IDLE) {
      printf("[conn][%p] Successfully shut down on idle.\n", Connection);
    } else {
      printf("[conn][%p] Shut down by transport, 0x%x\n", Connection,
             Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
    }
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
    //
    // The connection was explicitly shut down by the peer.
    //
    printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
           (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:

    // The connection has completed the shutdown process and is ready to be
    // safely cleaned up.

    printf("[conn][%p] All done\n", Connection);
    MsQuic->ConnectionClose(Connection);
    break;
  case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:

    // The peer has started/created a new stream. The app MUST set the
    // callback handler before returning.

    printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
    MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                               (void *)ServerStreamCallback, Context);
    break;
  case QUIC_CONNECTION_EVENT_RESUMED:

    // The connection succeeded in doing a TLS resumption of a previous
    // connection's session.

    printf("[conn][%p] Connection resumed!\n", Connection);
    break;
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

// The server's callback for listener events from MsQuic.
// Using context to send HTTPServer instance
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
    ServerListenerCallback(_In_ HQUIC Listener, _In_opt_ void *Context,
                           _Inout_ QUIC_LISTENER_EVENT *Event) {
  UNREFERENCED_PARAMETER(Listener);
  UNREFERENCED_PARAMETER(Context);
  QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
  switch (Event->Type) {
  case QUIC_LISTENER_EVENT_NEW_CONNECTION:
    // A new connection is being attempted by a client. For the handshake to
    // proceed, the server must provide a configuration for QUIC to use. The
    // app MUST set the callback handler before returning.
    MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection,
                               (void *)ServerConnectionCallback, Context);
    Status = MsQuic->ConnectionSetConfiguration(
        Event->NEW_CONNECTION.Connection, Configuration);
    break;
  default:
    break;
  }
  return Status;
}

