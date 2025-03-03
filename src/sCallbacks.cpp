#include <msquic.h>

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

#include "log.hpp"
#include "server.hpp"
#include "utils.hpp"

// #define QUIC_DEBUG

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    HttpServer::StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                               _Inout_ QUIC_STREAM_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);
  HttpServer *server = (HttpServer *)Context;

  // HTTPServer *server = HTTPServer::GetInstance();
  switch (Event->Type) {
  case QUIC_STREAM_EVENT_SEND_COMPLETE:

    // A previous StreamSend call has completed, and the context is being
    // returned back to the app.

    free(Event->SEND_COMPLETE.ClientContext);
#ifdef QUIC_DEBUG
    printf("[strm][%p] Data sent\n", Stream);
#endif
    break;
  case QUIC_STREAM_EVENT_RECEIVE:

#ifdef QUIC_DEBUG

    printf("[strm][%p] Data received\n", Stream);
#endif

    // If no previous allocated Buffer let's allocate one for this Stream
    if (server->QuicBufferMap.find(Stream) == server->QuicBufferMap.end()) {
      server->QuicBufferMap[Stream].reserve(256);
    }

    // Data was received from the peer on Stream.
    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

      uint8_t *bufferPointer = buffer->Buffer;
      uint8_t *bufferEnd = buffer->Buffer + buffer->Length;

      if (buffer->Length > 0) {
        auto &streamBuffer = server->QuicBufferMap[Stream];
        streamBuffer.insert(streamBuffer.end(), bufferPointer, bufferEnd);
      }
    }
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:

  {
    auto startTime = std::chrono::high_resolution_clock::now();
#ifdef QUIC_DEBUG

    printf("[strm][%p] Peer shut down\n", Stream);
#endif
    // The peer gracefully shut down its send direction of the stream.

    if (server->QuicBufferMap.find(Stream) == server->QuicBufferMap.end()) {
      std::ostringstream oss;
      oss << " No BufferMap found for Stream: " << Stream << "!";
      LogError(oss.str());
      break;
    }

    // Here we send the response to the request. (since by now the
    // request should be fully processed)

    std::string data;

    server->ParseStreamBuffer(Stream, server->QuicBufferMap[Stream], data);

    // std::unordered_map<std::string, std::string> headersMap;
#ifdef ECHO
    std::cout << "HTTP3 Request:\n";
    for (const auto &header : server->QuicDecodedHeadersMap[Stream]) {
      std::cout << header.first << ": " << header.second << "\n";
    }
    std::cout << data << std::endl;
#endif
    // bool acceptEncoding;

    // Validate Request
    server->ValidatePseudoHeaders(server->QuicDecodedHeadersMap[Stream]);

    // Route Request
    auto [headers, body] = server->ServerRouter->RouteRequest(
        server->QuicDecodedHeadersMap[Stream][":method"],
        server->QuicDecodedHeadersMap[Stream][":path"]);

    {
      std::unordered_map<std::string, std::string> headersMap;
      headersMap.reserve(2);

      HttpCore::RespHeaderToPseudoHeader(headers, headersMap);

      std::vector<uint8_t> encodedHeaders;

      // uint64_t streamId{};
      // auto len = (uint32_t)sizeof(streamId);
      //
      // if (QUIC_FAILED(MsQuic->GetParam(Stream, QUIC_PARAM_STREAM_ID, &len,
      //                                  &streamId))) {
      //   LogError("Failed to acquire stream id");
      // }

      server->EncodeQPACKHeaders(&Stream, headersMap, encodedHeaders);
      // HttpCore::QPACK_EncodeHeaders(streamId, headersMap, encodedHeaders);

      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);

      frames.emplace_back(
          server->BuildHttp3Frame(Frame::HEADERS, 0, encodedHeaders));

      frames.emplace_back(server->BuildHttp3Frame(Frame::DATA, 0, {}, body));

      server->SendBatch(Stream, frames, true);
      // HttpCore::HTTP3_SendFrames(Stream, frames);
    }

    auto endTime = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> elapsed = endTime - startTime;

    // std::cout << "Request handled in " << elapsed.count() << "
    // seconds\n";
    // std::ostringstream logStream;
    // logStream << "Protocol: HTTP3 "
    //           << "Method: " <<
    //           server->QuicDecodedHeadersMap[Stream][":method"]
    //           << " Path: " <<
    //           server->QuicDecodedHeadersMap[Stream][":path"]
    //           << " Status: " << status << " Elapsed time: " <<
    //           elapsed.count()
    //           << " s";
    //
    // LogRequest(logStream.str());

    server->QuicDecodedHeadersMap.erase(Stream);
    server->QuicBufferMap.erase(Stream);

  }

  break;
  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:

    // The peer aborted its send direction of the stream.
#ifdef QUIC_DEBUG

    printf("[strm][%p] Peer aborted\n", Stream);
#endif
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    break;
  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
// Both directions of the stream have been shut down and MsQuic is done
// with the stream. It can now be safely cleaned up.
#ifdef QUIC_DEBUG
    printf("[strm][%p] Stream officialy closed\n", Stream);
#endif

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
    HttpServer::ConnectionCallback(_In_ HQUIC Connection,
                                   _In_opt_ void *Context,
                                   _Inout_ QUIC_CONNECTION_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);

  // HTTPServer *server = (HTTPServer *)Context;

  switch (Event->Type) {
  case QUIC_CONNECTION_EVENT_CONNECTED:
#ifdef QUIC_DEBUG
    printf("[conn][%p] Connected\n", Connection);
#endif
    // The handshake has completed for the connection.

    // Send  resumption ticket for future interactions
    MsQuic->ConnectionSendResumptionTicket(
        Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);

    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:

    // The connection has been shut down by the transport. Generally, this
    // is the expected way for the connection to shut down with this
    // protocol, since we let idle timeout kill the connection.

#ifdef QUIC_DEBUG
    if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
        QUIC_STATUS_CONNECTION_IDLE) {
      printf("[conn][%p] Successfully shut down on idle.\n", Connection);
    } else {
      printf("[conn][%p] Shut down by transport, 0x%x\n", Connection,
             Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
    }
#endif

    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:

    // The connection was explicitly shut down by the peer.
#ifdef QUIC_DEBUG
    printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
           (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
#endif

    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:

    // The connection has completed the shutdown process and is ready to be
    // safely cleaned up.
#ifdef QUIC_DEBUG

    printf("[conn][%p] Connection officialy closed\n", Connection);
#endif
    MsQuic->ConnectionClose(Connection);
    break;
  case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:

    // The peer has started/created a new stream. The app MUST set the
    // callback handler before returning.
#ifdef QUIC_DEBUG

    printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
#endif
    MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                               (void *)HttpServer::StreamCallback, Context);

    break;
  case QUIC_CONNECTION_EVENT_RESUMED:

    printf("[conn][%p] Connection resumed!\n", Connection);
    // The connection succeeded in doing a TLS resumption of a previous
    // connection's session.
#ifdef QUIC_DEBUG

    printf("[conn][%p] Connection resumed!\n", Connection);
#endif
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
    HttpServer::ListenerCallback(_In_ HQUIC Listener, _In_opt_ void *Context,
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
                               (void *)HttpServer::ConnectionCallback, Context);
    Status = MsQuic->ConnectionSetConfiguration(
        Event->NEW_CONNECTION.Connection, Configuration);
    break;
  default:
    break;
  }
  return Status;
}
