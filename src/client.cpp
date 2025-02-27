#include "client.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>

#include "log.hpp"
#include "ssl.h"
#include "utils.hpp"

void HTTPClient::ParseRequestsFromFile(const std::string &filePath) {
  std::ifstream file(filePath);
  std::string line;
  std::string headers{};
  std::string body{};

  if (filePath.empty()) {
    std::cerr << "Invalid file name!" << std::endl;
    return;
  }

  if (!file.is_open()) {
    std::cerr << "Failed to open file: " << filePath << std::endl;
    return;
  }

  while (std::getline(file, line)) {
    // Skip empty lines
    if (line.empty())
      continue;

    // If the line starts with "Body:", save the body and store the request
    if (line.starts_with("Body:")) {
      body = line.substr(5);

      if (body.empty()) {
        requests.emplace_back(headers, body);
        headers.clear();
        continue;
      }

      while (std::getline(file, line)) {
        if (line.empty())
          break;

        body += "\r\n" + line;
      }

      if (body[0] == ' ') {
        body.erase(0, 1);
      }

      requests.emplace_back(headers, body);
      headers.clear();
      body.clear();

    } else {
      headers += line + "\r\n";
    }
  }

  if (!headers.empty() || !body.empty()) {
    requests.emplace_back(headers, body);
  }
}

HTTPClient::HTTPClient(int argc, char *argv[]) {
  struct addrinfo hints{};
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0; /* Any protocol */

  timeout = {};
  std::string serverPort = std::to_string(HTTP_PORT);
  std::string serverAddr = GetValue2(argc, argv, "target");

  if (serverAddr == "") {
    std::cout
        << "No target specified (-target:addr). Defaulting to localhost\n";
    serverAddr = "127.0.0.1";
  }

  // Should accept both names and IP addresses
  int s = getaddrinfo(serverAddr.c_str(), serverPort.c_str(), &hints,
                      &TCP_SocketAddr);
  if (s != 0) {
    LogError("getaddrinfo: " + std::string(gai_strerror(s)));
    exit(EXIT_FAILURE);
  }

  // TCP_Socket = socket(AF_INET, SOCK_STREAM, 0);
  // TCP_SocketAddress = {};
  // timeout = {};
  //
  // // timeout.tv_sec = TIMEOUT_SECONDS;
  // timeout.tv_sec = 0;
  // timeout.tv_usec = 100 * 1000;
  //
  // if (setsockopt(TCP_Socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
  //                sizeof timeout) == ERROR) {
  //   LogError(strerror(errno));
  // }
  //
  // timeout.tv_sec = 0;
  // timeout.tv_usec = 100 * 1000;
  //
  // if (setsockopt(TCP_Socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
  //                sizeof timeout) == ERROR) {
  //   LogError(strerror(errno));
  // }
  //
  // int buffSize = 256 * 1024; // 256 KB
  // setsockopt(TCP_Socket, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize));
  // setsockopt(TCP_Socket, SOL_SOCKET, SO_SNDBUF, &buffSize, sizeof(buffSize));

  // If we want ipv6 we need to use sockaddr_in6
  // Here we specify if we want a ipv4 or ipv6 struct

  // TCP_SocketAddress.sin_family = AF_INET;
  // TCP_SocketAddress.sin_port = htons(HTTP_PORT);

  // inet_ntop works in the reverse way
  // wont work with name such as localhost
  // for that purposew e need to use getaddrinfo()
  // Here we specify if we want a ipv4 or ipv6 struct
  // Need to convert string to uint32_t

  // if (inet_pton(AF_INET, serverAddr.c_str(), &TCP_SocketAddress.sin_addr) !=
  //     1) {
  //   LogError("Failed to convert serverAddr from text to binary");
  //   exit(EXIT_FAILURE);
  // }

  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  SSL_ctx = SSL_CTX_new(SSLv23_client_method());
  if (!SSL_ctx) {
    LogError("Failed to create SSL context");
    exit(EXIT_FAILURE);
  }

  SSL_CTX_set_timeout(SSL_ctx, 60);

  if (GetFlag(argc, argv, "unsecure")) {
    SSL_CTX_set_verify(SSL_ctx, SSL_VERIFY_NONE, NULL);
  }
  // else{
  //
  // }

  constexpr unsigned char alpnProtos[] = {
      2, 'h', '2',                              // HTTP/2
      8, 'h', 't', 't', 'p', '/', '1', '.', '1' // HTTP/1.1
  };

  // Set ALPN protocols
  if (SSL_CTX_set_alpn_protos(SSL_ctx, alpnProtos, sizeof(alpnProtos)) != 0) {
    std::cerr << "Failed to set ALPN protocols\n";
    exit(EXIT_FAILURE);
  }

  // Quic configuration
  if (!LoadQUICConfiguration(argc, argv)) {
    exit(EXIT_FAILURE);
  }

  // Load requests
  std::string requestsFile;

  if ((requestsFile = GetValue2(argc, argv, "requests")) != "") {
    ParseRequestsFromFile(requestsFile);
  }
}

void HTTPClient::PrintFromServer() { std::cout << "Hello from client\n"; }
HTTPClient::~HTTPClient() { std::cout << "Deconstructing Client" << std::endl; }

unsigned char HTTPClient::LoadQUICConfiguration(int argc, char *argv[]) {
  BOOLEAN Unsecure = GetFlag(argc, argv, "unsecure");

  QUIC_SETTINGS Settings = {0};
  // Configures the client's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;
  // Settings.StreamMultiReceiveEnabled = TRUE;

  // Configures a default client configuration, optionally disabling
  // server certificate validation.
  QUIC_CREDENTIAL_CONFIG CredConfig;
  memset(&CredConfig, 0, sizeof(CredConfig));
  CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
  if (Unsecure) {
    std::cout << "Unsecure connection\n";
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    std::ostringstream oss;
    oss << "ConfigurationOpen failed, 0x" << std::hex << Status;
    LogError(oss.str());

    return FALSE;
  }

  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration,
                                                               &CredConfig))) {
    std::ostringstream oss;
    oss << "ConfigurationLoadCredential failed, 0x" << std::hex << Status;
    LogError(oss.str());

    return FALSE;
  }

  return TRUE;
}

int HTTPClient::dhiProcessHeader(void *hblock_ctx,
                                 struct lsxpack_header *xhdr) {
  std::string headerKey(xhdr->buf + xhdr->name_offset, xhdr->name_len);
  std::string headerValue(xhdr->buf + xhdr->val_offset, xhdr->val_len);

  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx;
  HTTPClient *instance = (HTTPClient *)block_ctx->instance_ctx;

  instance->QuicDecodedHeadersMap[block_ctx->stream][headerKey] = headerValue;

  return 0;
}

void HTTPClient::HTTP2_RecvFrames_TS(SSL *ssl) {
  struct lshpack_dec dec{};
  lshpack_dec_init(&dec);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      TcpDecodedHeadersMap;

  // Buffer for encoded headers until decoding
  std::unordered_map<uint32_t, std::vector<uint8_t>> EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> TcpDataMap;

  // SSL_read buffers
  std::vector<uint8_t> buffer;
  std::vector<uint8_t> tmpBuffer(BUFFER_SIZE);

  const size_t FRAME_HEADER_LENGTH = 9;

  std::vector<uint8_t> frame;
  frame.reserve(FRAME_HEADER_LENGTH + 256);

  int offset = 0;

  int bytesReceived{};
  bool GOAWAY = false;
  size_t nResponses = 0;
  while (!GOAWAY) {
    {
      std::lock_guard<std::mutex> lock(TCP_MutexMap[ssl]);
      bytesReceived = SSL_read(ssl, tmpBuffer.data(), (int)tmpBuffer.size());
    }

    if (bytesReceived == 0) {
      LogError("Peer closed the connection");
      std::cout << "Peer closed the connection" << std::endl;
      break;
    } else if (bytesReceived < 0) {
      int error = SSL_get_error(ssl, bytesReceived);

      // Implement retrying here
      // Check if it was a timeout
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        // Timeout, let's wait for a bit and retry
        // std::cout << "Timeout occurred, retrying..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      } else {
        // LogError(GetSSLErrorMessage(error));
        // std::cout << "Failed to recv HTTP2 response fully" << std::endl;
        break;
      }
    }

    buffer.insert(buffer.end(), tmpBuffer.begin(),
                  tmpBuffer.begin() + bytesReceived);

    // If we received atleast the frame header
    while (offset + FRAME_HEADER_LENGTH <= buffer.size() && !GOAWAY) {
      uint8_t *framePtr = buffer.data() + offset;

      uint32_t payloadLength = (static_cast<uint32_t>(framePtr[0]) << 16) |
                               (static_cast<uint32_t>(framePtr[1]) << 8) |
                               static_cast<uint32_t>(framePtr[2]);

      if (offset + FRAME_HEADER_LENGTH + payloadLength > buffer.size()) {
        break;
      }

      uint8_t frameType = framePtr[3];

      uint8_t frameFlags = framePtr[4];

      uint32_t frameStream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                             (framePtr[7] << 8) | framePtr[8];

      // std::cout << "Payload Length: " << std::dec << (int)payloadLength
      //           << std::hex << ", Flags: " << (int)frameFlags << " ";

      switch (frameType) {
      case Frame::DATA:
        // std::cout << "[strm][" << frameStream << "] DATA frame\n";

        TcpDataMap[frameStream] += std::string(
            reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
            payloadLength);

        // std::cout << TcpDataMap[frameStream] << std::endl;

        if (isFlagSet(frameFlags, END_STREAM_FLAG)) {
          // HTTPServer::ValidatePseudoHeaders(TcpDecodedHeadersMap[frameStream]);

          std::cout << "Response:\n";
          for (const auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
            std::cout << key << ": " << value << "\n";
          }

          std::cout << TcpDataMap[frameStream] << "\n";

          // if (TcpDataMap[frameStream] != "Bad Request") {
          //   std::cout << " WE HAVE A PROBLEM: " << TcpDataMap[frameStream];
          // }
          // std::cout << std::endl;

          TcpDataMap.erase(frameStream);
          TcpDecodedHeadersMap.erase(frameStream);
          EncodedHeadersBufferMap.erase(frameStream);
          ++nResponses;
        }
        break;
      case Frame::HEADERS:
        // std::cout << "[strm][" << frameStream << "] HEADERS frame\n";

        {
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payloadLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and dispatch request

            HTTPBase::HPACK_DecodeHeaders(dec,
                                          TcpDecodedHeadersMap[frameStream],
                                          EncodedHeadersBufferMap[frameStream]);

            // HTTPServer::ValidatePseudoHeaders(
            //     TcpDecodedHeadersMap[frameStream]);

            TcpDataMap.erase(frameStream);
            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);
            ++nResponses;
          } else if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and wait for request body
            HTTPBase::HPACK_DecodeHeaders(dec,
                                          TcpDecodedHeadersMap[frameStream],
                                          EncodedHeadersBufferMap[frameStream]);
          }
        }
        break;
      case Frame::PRIORITY:
        // std::cout << "[strm][" << frameStream << "] PRIORITY frame\n";

        break;
      case 0x03:
        // std::cout << "[strm][" << frameStream
        //           << "] Received RST_STREAM frame\n";

        TcpDataMap.erase(frameStream);
        TcpDecodedHeadersMap.erase(frameStream);
        EncodedHeadersBufferMap.erase(frameStream);
        break;

      case Frame::SETTINGS:

        // std::cout << "[strm][" << frameStream << "] SETTINGS frame\n";

        // Only respond with an ACK to their SETTINGS frame with no ACK
        if (frameFlags == HTTP2Flags::NONE_FLAG) {
          HTTPBase::HTTP2_FillSettingsFrame(frame,
                                            HTTP2Flags::SETTINGS_ACK_FLAG);
          HTTPBase::HTTP2_SendFrame_TS(ssl, frame);
        }

        break;
      case Frame::GOAWAY:

        // std::cout << "[strm][" << frameStream << "] GOAWAY frame\n";
        GOAWAY = true;

        TcpDataMap.erase(frameStream);
        TcpDecodedHeadersMap.erase(frameStream);
        EncodedHeadersBufferMap.erase(frameStream);
        break;

      case Frame::WINDOW_UPDATE:

        // std::cout << "[strm][" << frameStream << "] WINDOW_UPDATE frame\n";

        break;

      case Frame::CONTINUATION:

        // std::cout << "[strm][" << frameStream << "] CONTINUATION frame\n";
        {
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payloadLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and dispatch request
            HTTPBase::HPACK_DecodeHeaders(dec,
                                          TcpDecodedHeadersMap[frameStream],
                                          EncodedHeadersBufferMap[frameStream]);

            // std::cout << "Response:\n";
            // for (const auto &[key, value] :
            // TcpDecodedHeadersMap[frameStream]) {
            //   std::cout << key << ": " << value << "\n";
            // }

            TcpDataMap.erase(frameStream);
            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);
            ++nResponses;
          } else if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and wait for request body
            HTTPBase::HPACK_DecodeHeaders(dec,
                                          TcpDecodedHeadersMap[frameStream],
                                          EncodedHeadersBufferMap[frameStream]);
          }
        }
        break;

      default:
        std::cout << "[strm][" << frameStream << "] Unknown frame type: 0x"
                  << std::dec << frameType << std::dec << "\n";
        break;
      }
      // Move the offset to the next frame
      offset += FRAME_HEADER_LENGTH + payloadLength;
    }

    // if (offset == buffer.size()) {
    //   buffer.clear();
    //   offset = 0;
    // }
  }
  std::cout << "Received: " << nResponses << "\n";

  lshpack_dec_cleanup(&dec);
}

void compareByteArrays(const std::vector<uint8_t> &expected,
                       const std::vector<uint8_t> &actual) {
  // Find the smallest size to avoid out-of-bounds access
  size_t size = std::min(expected.size(), actual.size());

  for (size_t i = 0; i < size; ++i) {
    if (expected[i] != actual[i]) {
      std::cout << "Bytes don't match at index " << i << ":\n";
      std::cout << "Expected byte: " << static_cast<int>(expected[i]) << "\n";
      std::cout << "Actual byte: " << static_cast<int>(actual[i]) << "\n";
    }
  }

  // If the sizes are different, report the mismatch at the last index.
  if (expected.size() != actual.size()) {
    std::cout << "Arrays have different sizes. Expected size: "
              << expected.size() << ", Actual size: " << actual.size() << "\n";
  } else {
    std::cout << "Both byte arrays size match.\n";
  }
}
// Here lets negotiate the protocol...
void HTTPClient::RunHTTP2(int argc, char *argv[]) {
  timeout.tv_sec = 0;
  timeout.tv_usec = 100 * 1000;
  static constexpr int buffSize = 256 * 1024; // 256 KB

  struct addrinfo *addr = nullptr;
  for (addr = TCP_SocketAddr; addr != nullptr; addr = addr->ai_next) {
    TCP_Socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (TCP_Socket == -1) {
      std::cout << "Failed....\n";
      continue;
    }

    // Handle errors here
    setsockopt(TCP_Socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    setsockopt(TCP_Socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

    setsockopt(TCP_Socket, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize));
    setsockopt(TCP_Socket, SOL_SOCKET, SO_SNDBUF, &buffSize, sizeof(buffSize));

    if (connect(TCP_Socket, addr->ai_addr, addr->ai_addrlen) == 0) {
      break;
    }

    close(TCP_Socket);
  }

  freeaddrinfo(TCP_SocketAddr);

  if (addr == nullptr) {
    LogError("Could not connect to any address");
    SSL_CTX_free(SSL_ctx);
    exit(EXIT_FAILURE);
  }

  SSL *ssl = SSL_new(SSL_ctx);
  SSL_set_fd(ssl, TCP_Socket);

  // Retry in case of failure
  int ret = SSL_connect(ssl);
  // TLS/SSL handshake
  if (ret <= 0) {
    int error = SSL_get_error(ssl, ret);
    LogError(GetSSLErrorMessage(error));
    std::cout << "SSL connection failed" << std::endl;
    SSL_free(ssl);
    close(TCP_Socket);
    SSL_CTX_free(SSL_ctx);
    return;
  }

  struct lshpack_enc enc{};
  lshpack_enc_init(&enc);

  // Send Preface, Window and SETTINGS
  std::vector<uint8_t> HTTP2_PrefaceBytes = {
      0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32,
      0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A};

  std::vector<uint8_t> frame;
  frame.reserve(FRAME_HEADER_LENGTH + 256);

  std::thread recvThread(&HTTPClient::HTTP2_RecvFrames_TS, this, ssl);

  {
    HTTPBase::HTTP2_FillSettingsFrame(frame, HTTP2Flags::NONE_FLAG);
    HTTPBase::HTTP2_SendFrame_TS(ssl, HTTP2_PrefaceBytes);
  }

  uint32_t numRequests = 0;
  uint32_t streamId = 1;

  for (const auto &request : requests) {
    // const auto &request = requests[0];
    const std::string &headers = request.first;
    const std::string &body = request.second;

    std::unordered_map<std::string, std::string> headersMap;

    HTTPBase::ReqHeaderToPseudoHeader(headers, headersMap);

    // Loop around here
    std::vector<uint8_t> encodedHeaders(1024);

    HTTPBase::HPACK_EncodeHeaders(enc, headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);

    frames.emplace_back(
        HTTPBase::HTTP2_BuildHeaderFrame(encodedHeaders, streamId));

    frames.emplace_back(HTTPBase::HTTP2_BuildDataFrame(body, streamId));

    // for (int i = 0; i < 1; ++i) {
    HTTPBase::HTTP2_SendFrames_TS(ssl, frames);
    streamId += 2;
    //}
  }

  {
    HTTPBase::HTTP2_FillGoAwayFrame(frame, 0, HTTP2ErrorCode::NO_ERROR);
    HTTPBase::HTTP2_SendFrame_TS(ssl, frame);
  }

  recvThread.join();

  lshpack_enc_cleanup(&enc);

  SSL_free(ssl);

  close(TCP_Socket);

  SSL_CTX_free(SSL_ctx);
}

void HTTPClient::Run(int argc, char *argv[]) {
  // std::thread http2Thread(&HTTPClient::RunHTTP2, this, argc, argv);
  // http2Thread.detach();

  RunHTTP2(argc, argv);
  //   QUIC_STATUS Status;
  //   const char *ResumptionTicketString = NULL;
  //   const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
  //   HQUIC Connection = NULL;
  //
  //   // Allocate a new connection object.
  //   if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(
  //                       Registration, HTTPClient::ConnectionCallback, this,
  //                       &Connection))) {
  //     printf("ConnectionOpen failed, 0x%x!\n", Status);
  //     goto Error;
  //   }
  //
  //   if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
  //     //
  //     // If provided at the command line, set the resumption ticket that can
  //     // be used to resume a previous session.
  //     //
  //     uint8_t ResumptionTicket[10240];
  //     uint16_t TicketLength = (uint16_t)DecodeHexBuffer(
  //         ResumptionTicketString, sizeof(ResumptionTicket),
  //         ResumptionTicket);
  //     if (QUIC_FAILED(Status = MsQuic->SetParam(
  //                         Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET,
  //                         TicketLength, ResumptionTicket))) {
  //       printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n",
  //              Status);
  //       goto Error;
  //     }
  //   }
  //
  //   if (SslKeyLogFile != NULL) {
  //     if (QUIC_FAILED(
  //             Status = MsQuic->SetParam(Connection,
  //             QUIC_PARAM_CONN_TLS_SECRETS,
  //                                       sizeof(ClientSecrets),
  //                                       &ClientSecrets))) {
  //       printf("SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x%x!\n",
  //       Status); goto Error;
  //     }
  //   }
  //
  //   // Get the target / server name or IP from the command line.
  //   const char *Target;
  //   if ((Target = GetValue(argc, argv, "target")) == NULL) {
  //     printf("Must specify '-target' argument!\n");
  //     Status = QUIC_STATUS_INVALID_PARAMETER;
  //     goto Error;
  //   }
  //
  //   printf("[conn][%p] Connecting...\n", Connection);
  //
  //   // Start the connection to the server.
  //   if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection,
  //   Configuration,
  //                                                    QUIC_ADDRESS_FAMILY_UNSPEC,
  //                                                    Target, UDP_PORT))) {
  //     printf("ConnectionStart failed, 0x%x!\n", Status);
  //     goto Error;
  //   }
  //
  // Error:
  //
  //   if (QUIC_FAILED(Status) && Connection != NULL) {
  //     MsQuic->ConnectionClose(Connection);
  //   }
}

void HTTPClient::QPACK_DecodeHeaders(HQUIC stream,
                                     std::vector<uint8_t> &encodedHeaders) {
  std::vector<struct lsqpack_dec> dec(1);

  uint64_t streamId{};
  uint32_t len = (uint32_t)sizeof(streamId);
  if (QUIC_FAILED(
          MsQuic->GetParam(stream, QUIC_PARAM_STREAM_ID, &len, &streamId))) {
    LogError("Failed to acquire stream id");
  }

  struct lsqpack_dec_hset_if hset_if;
  hset_if.dhi_unblocked = dhiUnblocked;
  hset_if.dhi_prepare_decode = dhiPrepareDecode;
  hset_if.dhi_process_header = HTTPClient::dhiProcessHeader;

  enum lsqpack_dec_opts dec_opts {};
  lsqpack_dec_init(dec.data(), NULL, 0x1000, 0, &hset_if, dec_opts);

  // hblock_ctx_t *blockCtx = (hblock_ctx_t *)malloc(sizeof(hblock_ctx_t));

  std::vector<hblock_ctx_t> blockCtx(1);

  memset(&blockCtx.back(), 0, sizeof(hblock_ctx_t));
  blockCtx.back().instance_ctx = this;
  blockCtx.back().stream = stream;

  const unsigned char *encodedHeadersPtr = encodedHeaders.data();
  size_t totalHeaderSize = encodedHeaders.size();

  enum lsqpack_read_header_status readStatus;

  readStatus = lsqpack_dec_header_in(dec.data(), &blockCtx.back(), streamId,
                                     totalHeaderSize, &encodedHeadersPtr,
                                     totalHeaderSize, NULL, NULL);

  lsqpack_dec_cleanup(dec.data());
}

// Parses stream buffer to retrieve headers payload and data payload
void HTTPClient::ParseStreamBuffer(HQUIC Stream,
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
    case 0x01: // HEADERS frame
      // std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

      {
        std::vector<uint8_t> encodedHeaders(iter, iter + frameLength);

        HTTPClient::QPACK_DecodeHeaders(Stream, encodedHeaders);

        // headers = std::string(iter, iter + frameLength);
      }

      break;

    case 0x00: // DATA frame
      // std::cout << "[strm][" << Stream << "] Received DATA frame\n";
      // Data might have been transmitted over multiple frames
      data += std::string(iter, iter + frameLength);
      break;

    default: // Unknown frame type
      std::cout << "[strm][" << Stream << "] Unknown frame type: 0x" << std::hex
                << frameType << std::dec << "\n";
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
