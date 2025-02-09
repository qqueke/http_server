#include "sCallbacks.hpp"

#include <cstdint>
#include <iostream>
#include <string>

#include "server.hpp"
#include "utils.hpp"

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ServerStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);
  HTTPServer *server = (HTTPServer *)Context;

  switch (Event->Type) {
  case QUIC_STREAM_EVENT_SEND_COMPLETE:

    // A previous StreamSend call has completed, and the context is being
    // returned back to the app.

    free(Event->SEND_COMPLETE.ClientContext);
    printf("[strm][%p] Data sent\n", Stream);
    break;
  case QUIC_STREAM_EVENT_RECEIVE:

    // If no previous allocated Buffer let's allocate one for this Stream
    if (server->BufferMap.find(Stream) == server->BufferMap.end()) {
      server->BufferMap[Stream].reserve(256);
    }

    // Data was received from the peer on Stream.
    printf("[strm][%p] Data received\n", Stream);

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

      uint8_t *bufferPointer = buffer->Buffer;
      uint8_t *bufferEnd = buffer->Buffer + buffer->Length;

      if (buffer->Length > 0) {
        auto &streamBuffer = server->BufferMap[Stream];
        streamBuffer.insert(streamBuffer.end(), bufferPointer, bufferEnd);
      }
    }
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:

    // The peer gracefully shut down its send direction of the stream.
    printf("[strm][%p] Peer shut down\n", Stream);

    if (server->BufferMap.find(Stream) == server->BufferMap.end()) {
      std::cout << "Error: no buffer found for Stream:" << Stream << "\n";
      break;
    }

    // Here we send the response to the request. (since by now the
    // request should be fully processed)

    {
      std::string headers;
      std::string data;

      ParseStreamBuffer(Stream, server->BufferMap[Stream], headers, data);

      std::unordered_map<std::string, std::string> headersMap;

      bool acceptEncoding;

      // Validate Request
      HTTPServer::ValidateHeadersHTTP3(headers, headersMap);

      // Route Request
      std::string status = server->ServerRouter->RouteRequest(
          headersMap[":method"], headersMap[":path"], data, Protocol::HTTP3,
          (void *)Stream);
    }
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:

    // The peer aborted its send direction of the stream.

    printf("[strm][%p] Peer aborted\n", Stream);
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    break;
  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
    // Both directions of the stream have been shut down and MsQuic is done
    // with the stream. It can now be safely cleaned up.
    printf("[strm][%p] Stream officialy closed\n", Stream);
    MsQuic->StreamClose(Stream);
    break;
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

// The server's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ServerConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);

  // HTTPServer *server = (HTTPServer *)Context;

  switch (Event->Type) {
  case QUIC_CONNECTION_EVENT_CONNECTED:

    // The handshake has completed for the connection.
    printf("[conn][%p] Connected\n", Connection);

    // Send  resumption ticket for future interactions
    // MsQuic->ConnectionSendResumptionTicket(
    //     Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);

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

    // The connection was explicitly shut down by the peer.

    printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
           (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:

    // The connection has completed the shutdown process and is ready to be
    // safely cleaned up.

    printf("[conn][%p] Connection officialy closed\n", Connection);
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
