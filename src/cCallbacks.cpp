#include <msquic.h>

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "client.hpp"
#include "log.hpp"
#include "utils.hpp"

// #define QUIC_DEBUG

void ClientSend(_In_ HQUIC Connection, void *Context) {
  HTTPClient *client = (HTTPClient *)Context;
  QUIC_STATUS Status;

  int i = 0;
  std::vector<HQUIC> Streams(client->requests.size());

  for (auto &[headers, body] : client->requests) {
    HQUIC &Stream = Streams[i++];

    // Create/allocate a new bidirectional stream. The stream is just
    // allocated and no QUIC stream identifier is assigned until it's started.
    // QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL
    if (QUIC_FAILED(Status = MsQuic->StreamOpen(
                        Connection, QUIC_STREAM_OPEN_FLAG_NONE,
                        HTTPClient::StreamCallback, Context, &Stream))) {
      printf("StreamOpen failed, 0x%x!\n", Status);
      if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
      }
    }

#ifdef QUIC_DEBUG
    printf("[strm][%p] Starting Stream...\n", Stream);
#endif
    // Starts the stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    // QUIC_STREAM_START_FLAG_NONE
    // QUIC_STREAM_START_FLAG_IMMEDIATE
    if (QUIC_FAILED(Status = MsQuic->StreamStart(
                        Stream, QUIC_STREAM_START_FLAG_NONE))) {
      printf("StreamStart failed, 0x%x!\n", Status);

      MsQuic->StreamClose(Stream);
      if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return;
      }
    }

    {
      std::unordered_map<std::string, std::string> headersMap;

      // Change this function to work for response and request
      HTTPBase::ReqHeaderToPseudoHeader(headers, headersMap);

      std::vector<uint8_t> encodedHeaders;

      uint64_t streamId{};
      uint32_t len = (uint32_t)sizeof(streamId);
      if (QUIC_FAILED(MsQuic->GetParam(Stream, QUIC_PARAM_STREAM_ID, &len,
                                       &streamId))) {
        LogError("Failed to acquire stream id");
      }

      HTTPBase::QPACK_EncodeHeaders(streamId, headersMap, encodedHeaders);

      // Put header frame and data frames in frames response
      std::vector<std::vector<uint8_t>> frames;

      // Build frames
      frames.emplace_back(HTTPBase::HTTP3_BuildHeaderFrame(encodedHeaders));

      frames.emplace_back(HTTPBase::HTTP3_BuildDataFrame(body));

      if (HTTPBase::HTTP3_SendFramesToNewConn(Connection, Stream, frames) ==
          -1) {
        return;
      }
    }
  }
}

// The clients's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    HTTPClient::StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                               _Inout_ QUIC_STREAM_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);

  HTTPClient *client = (HTTPClient *)Context;

  switch (Event->Type) {
  case QUIC_STREAM_EVENT_SEND_COMPLETE:
    // A previous StreamSend call has completed, and the context is being
    // returned back to the app.

    // We set the send context to be the pointer that we can latter free
    free(Event->SEND_COMPLETE.ClientContext);

#ifdef QUIC_DEBUG
    printf("[strm][%p] Data sent\n", Stream);
#endif
    break;
  case QUIC_STREAM_EVENT_RECEIVE:
    // Data was received from the peer on the stream.
#ifdef QUIC_DEBUG

    printf("[strm][%p] Data received\n", Stream);
#endif
    if (client->QuicBufferMap.find(Stream) == client->QuicBufferMap.end()) {
      client->QuicBufferMap[Stream].reserve(256);
    }

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

      uint8_t *bufferPointer = buffer->Buffer;
      uint8_t *bufferEnd = buffer->Buffer + buffer->Length;

      if (buffer->Length > 0) {
        auto &streamBuffer = client->QuicBufferMap[Stream];
        streamBuffer.insert(streamBuffer.end(), bufferPointer, bufferEnd);
      }
    }

    break;
  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:

    // The peer gracefully shut down its send direction of the stream.
#ifdef QUIC_DEBUG

    printf("[strm][%p] Peer aborted\n", Stream);
#endif
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    // The peer aborted its send direction of the stream.
#ifdef QUIC_DEBUG

    printf("[strm][%p] Peer shut down\n", Stream);
#endif
    if (client->QuicBufferMap.find(Stream) == client->QuicBufferMap.end()) {
      LogError("No buffer found for Stream");
      break;
    }

    {
      std::string headers;
      std::string data;

      client->ParseStreamBuffer(Stream, client->QuicBufferMap[Stream], data);

      if (client->QuicDecodedHeadersMap[Stream].find(":status") ==
          client->QuicDecodedHeadersMap[Stream].end()) {
        std::cout << "Error: Response missing :status field\n";
      } else {
        std::cout << "Status: "
                  << client->QuicDecodedHeadersMap[Stream][":status"] << " "
                  << data << std::endl;
      }
    }

    client->QuicDecodedHeadersMap.erase(Stream);
    client->QuicBufferMap.erase(Stream);

    break;
  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
    // Both directions of the stream have been shut down and MsQuic is done
    // with the stream. It can now be safely cleaned up.

#ifdef QUIC_DEBUG

    printf("[strm][%p] Stream is officially closed\n", Stream);
#endif
    if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
      MsQuic->StreamClose(Stream);
    }
    break;
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

// The clients's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    HTTPClient::ConnectionCallback(_In_ HQUIC Connection,
                                   _In_opt_ void *Context,
                                   _Inout_ QUIC_CONNECTION_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);

  if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
    const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
    if (SslKeyLogFile != NULL) {
      WriteSslKeyLogFile(SslKeyLogFile, &ClientSecrets);
    }
  }

  switch (Event->Type) {
  case QUIC_CONNECTION_EVENT_CONNECTED:
//
// The handshake has completed for the connection.
#ifdef QUIC_DEBUG

    printf("[conn][%p] Connected\n", Connection);
#endif

    ClientSend(Connection, Context);
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
#ifdef QUIC_DEBUG

    printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
           (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
#endif
    // The connection was explicitly shut down by the peer.
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
    // The connection has completed the shutdown process and is ready to
    // be safely cleaned up.

#ifdef QUIC_DEBUG

    printf("[conn][%p] Connection officially closed\n", Connection);
#endif
    if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
      MsQuic->ConnectionClose(Connection);
    }
    break;
  case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
// A resumption ticket (also called New Session Ticket or NST) was
// received from the server.
#ifdef QUIC_DEBUG
    printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection,
           Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
#endif

    // for (uint32_t i = 0;
    //      i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
    //      i++)
    //      {
    //   printf("%.2X",
    //          (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
    // }
    // printf("\n");
    break;
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}
