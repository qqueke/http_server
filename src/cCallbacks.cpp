// #include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
#include "cCallbacks.hpp"

#include <array>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "utils.hpp"

void ClientSend(_In_ HQUIC Connection) {
  QUIC_STATUS Status;

  // Create/allocate a new bidirectional stream. The stream is just allocated
  // and no QUIC stream identifier is assigned until it's started.
  HQUIC Stream;
  // std::cout << "Stream: " << i++ << "\n";
  if (QUIC_FAILED(
          Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE,
                                      ClientStreamCallback, NULL, &Stream))) {
    printf("StreamOpen failed, 0x%x!\n", Status);
    if (QUIC_FAILED(Status)) {
      MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                 0);
      return;
    }
  }

  printf("[strm][%p] Starting Stream...\n", Stream);

  // Starts the bidirectional stream. By default, the peer is not notified of
  // the stream being started until data is sent on the stream.
  //  QUIC_STREAM_START_FLAG_NONE
  // QUIC_STREAM_START_FLAG_IMMEDIATE
  if (QUIC_FAILED(
          Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
    printf("StreamStart failed, 0x%x!\n", Status);

    std::cout << "Shutting down Stream..." << std::endl;
    MsQuic->StreamClose(Stream);
    if (QUIC_FAILED(Status)) {
      MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                 0);
      return;
    }
  }

  // std::this_thread::sleep_for(std::chrono::milliseconds(10000));
  std::string compressedHeaders = ":method: GET\r\n"
                                  ":scheme: https\r\n"
                                  ":authority: qqueke\r\n"
                                  ":path: /hello\r\n"
                                  "user-agent: custom-client/1.0\r\n"
                                  "accept: */*\r\n";

  // Construct the frame header for Headers
  uint8_t frameType = 0x01; // 0x01 for HEADERS frame
  size_t payloadLength = compressedHeaders.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType); // Frame Type

  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength); // Frame Length

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payloadLength);
  memcpy(framePayload.data(), compressedHeaders.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> headerFrame(totalFrameSize);
  memcpy(headerFrame.data(), frameHeader.data(), frameHeader.size());
  memcpy(headerFrame.data() + frameHeader.size(), framePayload.data(),
         payloadLength);

  std::vector<std::vector<uint8_t>> frames;

  frames.emplace_back(headerFrame);


  // Add data frames here and append them to the frames

  if (SendFramesToNewConn(Connection, Stream, frames) == -1) {
    return;
  }
}

// The clients's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);

  switch (Event->Type) {
  case QUIC_STREAM_EVENT_SEND_COMPLETE:
    // A previous StreamSend call has completed, and the context is being
    // returned back to the app.

    // We set the send context to be the pointer that we can latter free
    free(Event->SEND_COMPLETE.ClientContext);
    printf("[strm][%p] Data sent\n", Stream);

    break;
  case QUIC_STREAM_EVENT_RECEIVE:
    // Data was received from the peer on the stream.
    printf("[strm][%p] Data received\n", Stream);

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

      uint8_t *bufferPointer = buffer->Buffer;
      std::vector<uint8_t> framePayload(bufferPointer,
                                        bufferPointer + buffer->Length);
      std::string payloadStr(framePayload.begin(), framePayload.end());

      std::cout << "Payload:\n" << payloadStr << "\n";
    }

    break;
  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    //
    // The peer gracefully shut down its send direction of the stream.
    //
    printf("[strm][%p] Peer aborted\n", Stream);
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    // The peer aborted its send direction of the stream.
    printf("[strm][%p] Peer shut down\n", Stream);
    break;
  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
    // Both directions of the stream have been shut down and MsQuic is done
    // with the stream. It can now be safely cleaned up.
    printf("[strm][%p] Stream is officially closed\n", Stream);
    if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
      std::cout << "Shutting down Stream..." << std::endl;

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
    ClientConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);

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
    //
    printf("[conn][%p] Connected\n", Connection);
    ClientSend(Connection);

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
    printf("[conn][%p] Connection officially closed\n", Connection);
    if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
      MsQuic->ConnectionClose(Connection);
    }
    break;
  case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
    // A resumption ticket (also called New Session Ticket or NST) was
    // received from the server.
    printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection,
           Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
    // for (uint32_t i = 0;
    //      i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++)
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
