#include "quicserver.hpp"

#include <format>
#include <iostream>
#include <sstream>

#include "log.hpp"
#include "server.hpp"

static uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                           const std::vector<uint8_t>::iterator &end) {
  // Check if there's enough data for at least the first byte
  if (iter + 1 >= end) {
    LogError("Buffer overflow in ReadVarint");
    return ERROR;
  }

  // Read the first byte
  uint64_t value = *iter++;
  uint8_t prefix =
      value >> 6;  // Get the prefix to determine the length of the varint
  size_t length = 1 << prefix;  // 1, 2, 4, or 8 bytes

  value &= 0x3F;  // Mask out the 2 most significant bits

  // Check if we have enough data for the full varint
  if (iter + length - 1 >= end) {
    LogError("Error: Not enough data in buffer for full varint\n");
    return ERROR;
  }

  // Read the remaining bytes of the varint
  for (size_t i = 1; i < length; ++i) {
    value = (value << 8) | *iter++;
  }

  return value;
}

void QuicServer::ParseStreamBuffer(HQUIC Stream,
                                   std::vector<uint8_t> &streamBuffer,
                                   std::string &data) {
  auto iter = streamBuffer.begin();

  while (iter < streamBuffer.end()) {
    // Ensure we have enough data for a frame (frameType + frameLength)
    if (std::distance(iter, streamBuffer.end()) < 3) {
      // std::cout << "Error: Bad frame format (Not enough data)\n";
      break;
    }

    // Read the frame type
    uint64_t frameType = ReadVarint(iter, streamBuffer.end());

    // Read the frame length
    uint64_t frameLength = ReadVarint(iter, streamBuffer.end());

    // Ensure the payload doesn't exceed the bounds of the buffer
    if (std::distance(iter, streamBuffer.end()) < frameLength) {
      std::cout << "Error: Payload exceeds buffer bounds\n";
      break;
    }

    // Handle the frame based on the type
    switch (frameType) {
      case Frame::DATA:  // DATA frame
        // std::cout << "[strm][" << Stream << "] Received DATA frame\n";
        // Data might have been transmitted over multiple frames
        data += std::string(iter, iter + frameLength);
        break;

      case Frame::HEADERS:
        // std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

        {
          std::vector<uint8_t> encodedHeaders(iter, iter + frameLength);

          // HttpClient::QPACK_DecodeHeaders(Stream, encodedHeaders);

          codec->Decode(&Stream, encodedHeaders, QuicDecodedHeadersMap[Stream]);

          // headers = std::string(iter, iter + frameLength);
        }

        break;

      default:  // Unknown frame type
        std::cout << "[strm][" << Stream << "] Unknown frame type: 0x"
                  << std::hex << frameType << std::dec << "\n";
        break;
    }

    iter += frameLength;
  }
  // std::cout << headers << data << "\n";

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < streamBuffer.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << Stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    streamBuffer.end() - iter);
    std::cout << std::endl;
  }
}

static void ValidatePseudoHeadersTmp(
    std::unordered_map<std::string, std::string> &headersMap) {
  static constexpr std::array<std::string_view, 3> requiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : requiredHeaders) {
    if (headersMap.find(std::string(header)) == headersMap.end()) {
      // LogError("Failed to validate pseudo-headers (missing header field)");
      headersMap[":method"] = "BR";
      headersMap[":path"] = "";
      return;
    }
  }
}

QuicServer::QuicServer(const std::shared_ptr<Router> &router, int argc,
                       char *argv[])
    : router(router), Status(0), Listener(nullptr) {
  codec = std::make_shared<QpackCodec>();

  transport = std::make_shared<QuicTransport>();

  frameBuilder = std::make_shared<Http3FrameBuilder>();

  Address = {0};
  QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&Address, UDP_PORT);

  // Load the server configuration based on the command line.
  if (!LoadConfiguration(argc, argv)) {
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }

  // Create/allocate a new listener object.
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ListenerCallback,
                                                (void *)this, &Listener))) {
    LogError(std::format("ListenerStart failed, 0x{:x}!", Status));
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }
}

QuicServer::~QuicServer() {}

void QuicServer::Run() {
  if (QUIC_FAILED(Status =
                      MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
    // printf("ListenerStart failed, 0x%x!\n", Status);
    std::ostringstream oss;
    oss << "ListenerStart failed, 0x" << std::hex << Status << "!";
    LogError(oss.str());

    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }
}

int QuicServer::LoadConfiguration(_In_ int argc,
                                  _In_reads_(argc)
                                      _Null_terminated_ char *argv[]) {
  QUIC_SETTINGS Settings = {0};

  // Configures the server's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;

  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  Settings.PeerBidiStreamCount = 100;
  Settings.IsSet.PeerBidiStreamCount = TRUE;
  Settings.PeerUnidiStreamCount = 2;
  Settings.IsSet.PeerUnidiStreamCount = TRUE;

  // Settings.StreamMultiReceiveEnabled = TRUE;

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  const char *Cert;
  const char *KeyFile;
  if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
    // Load the server's certificate from the default certificate store,
    // using the provided certificate hash.

    uint32_t CertHashLen = DecodeHexBuffer(
        Cert, sizeof(Config.CertHash.ShaHash), Config.CertHash.ShaHash);
    if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
      return FALSE;
    }
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
    Config.CredConfig.CertificateHash = &Config.CertHash;

  } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
             (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
    // Loads the server's certificate from the file.
    const char *Password = GetValue(argc, argv, "password");
    if (Password != NULL) {
      Config.CertFileProtected.CertificateFile = (char *)Cert;
      Config.CertFileProtected.PrivateKeyFile = (char *)KeyFile;
      Config.CertFileProtected.PrivateKeyPassword = (char *)Password;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
      Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
    } else {
      Config.CertFile.CertificateFile = (char *)Cert;
      Config.CertFile.PrivateKeyFile = (char *)KeyFile;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
      Config.CredConfig.CertificateFile = &Config.CertFile;
    }

  } else {
    printf(
        "Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and "
        "optionally 'password')]!\n");
    return FALSE;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    std::ostringstream oss;
    oss << "ConfigurationOpen failed, 0x" << std::hex << status;
    LogError(oss.str());

    return FALSE;
  }

  // Leaks here
  // Loads the TLS credential part of the configuration.
  if (QUIC_FAILED(status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig))) {
    std::ostringstream oss;
    oss << "ConfigurationLoadCredential failed, 0x" << std::hex << status;
    LogError(oss.str());
    return FALSE;
  }

  return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    QuicServer::StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                               _Inout_ QUIC_STREAM_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);
  QuicServer *server = (QuicServer *)Context;

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
      ValidatePseudoHeadersTmp(server->QuicDecodedHeadersMap[Stream]);

      // Route Request
      auto [headers, body] = server->router.lock()->RouteRequest(
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

        server->codec->Encode(&Stream, headersMap, encodedHeaders);
        // HttpCore::QPACK_EncodeHeaders(streamId, headersMap, encodedHeaders);

        std::vector<std::vector<uint8_t>> frames;
        frames.reserve(2);

        frames.emplace_back(server->frameBuilder->BuildFrame(Frame::HEADERS, 0,
                                                             encodedHeaders));

        frames.emplace_back(
            server->frameBuilder->BuildFrame(Frame::DATA, 0, {}, body));

        server->transport->SendBatch(Stream, frames);
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
    QuicServer::ConnectionCallback(_In_ HQUIC Connection,
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
                                 (void *)QuicServer::StreamCallback, Context);

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
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
    QuicServer::ListenerCallback(_In_ HQUIC Listener, _In_opt_ void *Context,
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
                                 (void *)QuicServer::ConnectionCallback,
                                 Context);
      Status = MsQuic->ConnectionSetConfiguration(
          Event->NEW_CONNECTION.Connection, Configuration);
      break;
    default:
      break;
  }
  return Status;
}
