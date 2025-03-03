#include "client.hpp"

#include <poll.h>
#include <sys/poll.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>

#include "log.hpp"
#include "ssl.h"
#include "utils.hpp"

// #define HTTP2_DEBUG

void HttpClient::ParseRequestsFromFile(const std::string &filePath) {
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

HttpClient::HttpClient(int argc, char *argv[]) {
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

  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  SSL_ctx = SSL_CTX_new(SSLv23_client_method());
  if (!SSL_ctx) {
    LogError("Failed to create SSL context");
    exit(EXIT_FAILURE);
  }

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

void HttpClient::PrintFromServer() { std::cout << "Hello from client\n"; }
HttpClient::~HttpClient() {
  SSL_CTX_free(SSL_ctx);
  std::cout << "Deconstructing Client" << std::endl;
}

unsigned char HttpClient::LoadQUICConfiguration(int argc, char *argv[]) {
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

void HttpClient::HTTP2_RecvFrames_TS(SSL *ssl) {
  struct lshpack_dec dec{};
  lshpack_dec_init(&dec);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      TcpDecodedHeadersMap;

  // Buffer for encoded headers until decoding
  std::unordered_map<uint32_t, std::vector<uint8_t>> EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> TcpDataMap;

  std::vector<uint8_t> buffer;
  buffer.reserve(65535);

  std::vector<uint8_t> frame;
  frame.reserve(FRAME_HEADER_LENGTH + 256);

  bool GOAWAY = false;
  size_t nResponses = 0;

  uint32_t connectionWindowSize{};
  std::unordered_map<uint32_t, uint32_t> streamWindowSizeMap;

  // Change this to bitset
  bool expectingContFrame = false;

  uint32_t nRequests = 0;
  uint8_t retryCount = 0;
  int bytesReceived = 0;
  int readOffset = 0;
  int writeOffset = 0;
  size_t nReadableBytes = 0;

  while (!GOAWAY) {
    bytesReceived = Receive_TS(ssl, buffer, writeOffset, TCP_MutexMap[ssl]);
    if (bytesReceived == ERROR) {
      break;
    }

    writeOffset += bytesReceived;
    nReadableBytes += (size_t)bytesReceived;

    retryCount = 0;

    // If we received atleast the frame header
    while (FRAME_HEADER_LENGTH <= nReadableBytes && !GOAWAY) {
      uint8_t *framePtr = buffer.data() + readOffset;

      uint32_t payloadLength = (static_cast<uint32_t>(framePtr[0]) << 16) |
                               (static_cast<uint32_t>(framePtr[1]) << 8) |
                               static_cast<uint32_t>(framePtr[2]);

      // if (offset + FRAME_HEADER_LENGTH + payloadLength > buffer.size()) {
      //   break;
      // }

      uint8_t frameType = framePtr[3];

      uint8_t frameFlags = framePtr[4];

      uint32_t frameStream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                             (framePtr[7] << 8) | framePtr[8];

      if (FRAME_HEADER_LENGTH + payloadLength > nReadableBytes) {
        std::cout << "Not enough data: " << FRAME_HEADER_LENGTH + payloadLength
                  << " with readable: " << nReadableBytes << std::endl;
        break;
      }

      if (expectingContFrame && frameType != Frame::CONTINUATION) {
        GOAWAY = true;
        Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                  HTTP2ErrorCode::PROTOCOL_ERROR));
        break;
      }

      switch (frameType) {
      case Frame::DATA:

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream << "] DATA frame\n";
#endif
        TcpDataMap[frameStream] += std::string(
            reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
            payloadLength);

        // std::cout << TcpDataMap[frameStream] << std::endl;

        if (isFlagSet(frameFlags, END_STREAM_FLAG)) {
          // HTTPServer::ValidatePseudoHeaders(TcpDecodedHeadersMap[frameStream]);

#ifdef ECHO
          std::cout << "Response:\n";
          for (const auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
            std::cout << key << ": " << value << "\n";
          }

          std::cout << TcpDataMap[frameStream] << "\n";
#endif
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
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream << "] HEADERS frame\n";
#endif

        if (frameStream == 0) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::PROTOCOL_ERROR));
          break;
        }

        {
          uint8_t *headerBlockStart = framePtr + FRAME_HEADER_LENGTH;
          uint8_t *payloadEnd = headerBlockStart + payloadLength;
          uint8_t padLength = 0;

          if (isFlagSet(frameFlags, HTTP2Flags::PADDED_FLAG)) {
            padLength = headerBlockStart[0];
            ++headerBlockStart; // Jump over pad length
          }

          if (isFlagSet(frameFlags, HTTP2Flags::PRIORITY_FLAG)) {
            headerBlockStart += 4; // Jump over stream dependency
            ++headerBlockStart;    // Jump over weight
          }

          uint32_t headerBlockLength =
              payloadEnd - headerBlockStart - padLength;

          if (headerBlockStart + headerBlockLength > payloadEnd) {
            Send(ssl, BuildHttp2Frame(Frame::RST_STREAM, 0, frameStream,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR));
            break;
          }

          // Do we really need to buffer the header blocks?
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(), headerBlockStart,
              headerBlockStart + headerBlockLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);

#ifdef ECHO
            std::cout << "Response: \n";
            for (auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
              std::cout << key << ": " << value << "\n";
            }
            std::cout << TcpDataMap[frameStream] << std::endl;
#endif
            Send(ssl, BuildHttp2Frame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

            ++nRequests;
            TcpDataMap.erase(frameStream);
            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);
            break;
          }

          if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);
          } else {
            expectingContFrame = true;
          }
        }

        break;
      case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream << "] PRIORITY frame\n";
#endif

        break;
      case Frame::RST_STREAM:
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream
                  << "] Received RST_STREAM frame\n";
#endif
        if (frameStream == 0) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::PROTOCOL_ERROR));
          break;
        } else if (payloadLength != 4) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::FRAME_SIZE_ERROR));
          break;
        }

        {
          uint32_t error = (framePtr[9] << 24) | (framePtr[10] << 16) |
                           (framePtr[11] << 8) | framePtr[12];
        }
        TcpDataMap.erase(frameStream);
        TcpDecodedHeadersMap.erase(frameStream);
        EncodedHeadersBufferMap.erase(frameStream);
        break;

      case Frame::SETTINGS:
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream << "] SETTINGS frame\n";
#endif
        if (payloadLength % 6 != 0) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::FRAME_SIZE_ERROR));
          break;
        } else if (frameStream != 0) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::FRAME_SIZE_ERROR));
          break;
        }

        if (isFlagSet(frameFlags, HTTP2Flags::NONE_FLAG)) {
          // Parse their settings and update this connection settings
          // to be the minimum between ours and theirs

          Send(ssl,
               BuildHttp2Frame(Frame::SETTINGS, HTTP2Flags::SETTINGS_ACK_FLAG));
        } else if (isFlagSet(frameFlags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
          if (payloadLength != 0) {
            GOAWAY = true;
            Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR));
            break;
          }
          // Received ACK to our settings
        }

        break;

      case Frame::PING:

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream << "] PING frame\n";
#endif

        // This is used to measure minimal round-trip (useful for graceful
        // shutdown with goaway)

        if (frameStream != 0) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::PROTOCOL_ERROR));
          break;
        } else if (payloadLength != 8) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::FRAME_SIZE_ERROR));
          break;
        }

        if (!isFlagSet(frameFlags, HTTP2Flags::PING_ACK_FLAG)) {
          {
            if (frame.size() != FRAME_HEADER_LENGTH + payloadLength) {
              frame.resize(FRAME_HEADER_LENGTH + payloadLength);
            }

            memcpy(frame.data(), framePtr, FRAME_HEADER_LENGTH + payloadLength);
            frame[4] = HTTP2Flags::PING_ACK_FLAG;

            Send(ssl, frame);
          }
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

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream << "] WINDOW_UPDATE frame\n";
#endif
        {
          uint32_t windowIncrement = (framePtr[9] << 24) |
                                     (framePtr[10] << 16) |
                                     (framePtr[11] << 8) | framePtr[12];

          // std::cout << "Window increment: " << windowIncrement << "\n";
          if (windowIncrement == 0) {
            GOAWAY = true;
            Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR));
            break;
          } else if (payloadLength != 4) {
            GOAWAY = true;
            Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR));
            break;
          }

          if (frameStream == 0) {
            connectionWindowSize += windowIncrement;
            if (connectionWindowSize > MAX_FLOW_WINDOW_SIZE) {
              GOAWAY = true;
              Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FLOW_CONTROL_ERROR));
              break;
            }
          } else {
            streamWindowSizeMap[frameStream] += windowIncrement;
            if (streamWindowSizeMap[frameStream] > MAX_FLOW_WINDOW_SIZE) {
              Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FLOW_CONTROL_ERROR));
              break;
            }
          }
        }

        break;

      case Frame::CONTINUATION:

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frameStream << "] CONTINUATION frame\n";
#endif
        if (frameStream == 0) {
          GOAWAY = true;
          Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                    HTTP2ErrorCode::PROTOCOL_ERROR));
          break;
        }

        {
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payloadLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and dispatch request
            DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);

#ifdef ECHO
            std::cout << "Response:\n";
            for (const auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
              std::cout << key << ": " << value << "\n";
            }
#endif
            TcpDataMap.erase(frameStream);
            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);
            ++nResponses;
            break;
          }

          if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            expectingContFrame = false;
            // Decode and wait for request body
            DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);
          }
          // Expecting another continuation frame ...
          else {
            expectingContFrame = true;
          }
        }
        break;

      default:
        std::cout << "[strm][" << frameStream << "] Unknown frame type: 0x"
                  << std::dec << frameType << std::dec << "\n";
        break;
      }
      // Move the offset to the next frame
      readOffset += (int)FRAME_HEADER_LENGTH + payloadLength;

      // Decrement readably bytes by the current frame size
      nReadableBytes -= (size_t)FRAME_HEADER_LENGTH + payloadLength;
    }

    if (nReadableBytes == 0) {
      writeOffset = 0;
      readOffset = 0;
    }
  }
  std::cout << "Received: " << nResponses << "\n";

  lshpack_dec_cleanup(&dec);
}

void HttpClient::SendHTTP1Request(SSL *ssl) {
  std::cout << "Opsie that is not available...\n";
}

void HttpClient::SendHTTP2Request(SSL *ssl) {
  struct lshpack_enc enc{};
  lshpack_enc_init(&enc);

  // Send Preface, Window and SETTINGS
  std::vector<uint8_t> HTTP2_PrefaceBytes = {
      0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32,
      0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A};

  std::vector<uint8_t> frame;
  frame.reserve(FRAME_HEADER_LENGTH + 256);

  std::thread recvThread(&HttpClient::HTTP2_RecvFrames_TS, this, ssl);

  Send(ssl, HTTP2_PrefaceBytes);

  uint32_t numRequests = 0;
  uint32_t streamId = 1;

  for (const auto &request : requests) {
    // const auto &request = requests[0];
    const std::string &headers = request.first;
    const std::string &body = request.second;

    std::unordered_map<std::string, std::string> headersMap;

    HttpCore::ReqHeaderToPseudoHeader(headers, headersMap);

    // Loop around here
    std::vector<uint8_t> encodedHeaders(1024);

    // HttpCore::HPACK_EncodeHeaders(enc, headersMap, encodedHeaders);

    EncodeHPACKHeaders(enc, headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);
    std::vector<uint8_t> frame =
        BuildHttp2Frame(Frame::HEADERS, 0, streamId, 0, 0, encodedHeaders);

    frames.emplace_back(frame);
    frame = BuildHttp2Frame(Frame::DATA, 0, streamId, 0, 0, {}, body);

    frames.emplace_back(frame);

    SendBatch(ssl, frames);
    streamId += 2;
  }

  Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0, HTTP2ErrorCode::NO_ERROR));

  recvThread.join();

  lshpack_enc_cleanup(&enc);
}

void HttpClient::RunTCP(int argc, char *argv[]) {
  timeout.tv_sec = 0;
  timeout.tv_usec = 100 * 1000;
  static constexpr int buffSize = 256 * 1024; // 256 KB

  struct addrinfo *addr = nullptr;
  for (addr = TCP_SocketAddr; addr != nullptr; addr = addr->ai_next) {
    TCP_Socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (TCP_Socket == -1) {
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
    return;
  }

  // Error handling..
  SSL *ssl = SSL_new(SSL_ctx);
  SSL_set_fd(ssl, TCP_Socket);

  struct pollfd pfd{};
  pfd.fd = TCP_Socket;
  pfd.events = POLLIN | POLLOUT | POLLHUP;

  while (true) {
    int ret = SSL_connect(ssl);
    if (ret > 0) {
      break;
    }

    int error = SSL_get_error(ssl, ret);
    if (error == SSL_ERROR_WANT_READ) {
      // pfd.events = POLLIN;
      poll(&pfd, 1, 1000);
      continue;
    } else if (error == SSL_ERROR_WANT_WRITE) {
      // pfd.events = POLLOUT;
      poll(&pfd, 1, 1000);
      continue;
    } else {
      LogError(GetSSLErrorMessage(error));
      SSL_free(ssl);
      close(TCP_Socket);
      return;
    }
  }

  const unsigned char *protocol = nullptr;
  unsigned int protocolLen = 0;
  SSL_get0_alpn_selected(ssl, &protocol, &protocolLen);

  if (protocolLen == 2 && memcmp(protocol, "h2", 2) == 0) {
    SendHTTP2Request(ssl);
  } else if (protocolLen == 8 && memcmp(protocol, "http/1.1", 8) == 0) {
    SendHTTP1Request(ssl);
  } else {
    LogError("Unsupported protocol or ALPN negotiation failed");
  }

  SSL_free(ssl);

  close(TCP_Socket);
}

std::vector<uint8_t> ReadResumptionTicketFromFile() {
  const std::string filename = "ticket"; // Hardcoded filename
  uint32_t ticketLength = 0;

  // Open the file in binary mode
  std::ifstream inFile(filename, std::ios::binary);

  if (inFile.is_open()) {
    // Read the length of the resumption ticket
    inFile.read(reinterpret_cast<char *>(&ticketLength), sizeof(ticketLength));
    uint32_t hostOrder = ntohl(ticketLength);

    // Read the ticket data into a vector of bytes
    std::vector<uint8_t> ticketData(hostOrder);
    inFile.read(reinterpret_cast<char *>(ticketData.data()), hostOrder);

    inFile.close();

    return ticketData;
  }

  std::cout << "Failed to open file for reading: " << filename << std::endl;
  return {};
}

void HttpClient::Run(int argc, char *argv[]) {
  // std::thread http2Thread(&HTTPClient::RunHTTP2, this, argc, argv);
  // http2Thread.detach();

  // RunTCP(argc, argv);

  QUIC_STATUS Status;
  const char *ResumptionTicketString = NULL;
  const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
  HQUIC Connection = NULL;

  std::vector<uint8_t> ticket;

  // Allocate a new connection object.
  if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(
                      Registration, HttpClient::ConnectionCallback, this,
                      &Connection))) {
    printf("ConnectionOpen failed, 0x%x!\n", Status);
    goto Error;
  }

  if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
    // If provided at the command line, set the resumption ticket that can
    // be used to resume a previous session.

    std::cout << "ResumptionTicketString len: "
              << strlen(ResumptionTicketString) << "\n";
    uint8_t ResumptionTicket[10240];
    uint16_t TicketLength = (uint16_t)DecodeHexBuffer(
        ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
    if (QUIC_FAILED(Status = MsQuic->SetParam(
                        Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET,
                        TicketLength, ResumptionTicket))) {
      printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n",
             Status);
      goto Error;
    }
  }

  else if (!(ticket = ReadResumptionTicketFromFile()).empty()) {
    std::cout << "Found ticket file\n";

    if (QUIC_FAILED(Status = MsQuic->SetParam(Connection,
                                              QUIC_PARAM_CONN_RESUMPTION_TICKET,
                                              ticket.size(), ticket.data()))) {
      printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n",
             Status);
      goto Error;
    }
  }

  if (SslKeyLogFile != NULL) {
    if (QUIC_FAILED(
            Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS,
                                      sizeof(ClientSecrets), &ClientSecrets))) {
      printf("SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x%x!\n", Status);
      goto Error;
    }
  }

  // Get the target / server name or IP from the command line.
  const char *Target;
  if ((Target = GetValue(argc, argv, "target")) == NULL) {
    printf("Must specify '-target' argument!\n");
    Status = QUIC_STATUS_INVALID_PARAMETER;
    goto Error;
  }

  printf("[conn][%p] Connecting...\n", Connection);

  // Start the connection to the server.
  if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration,
                                                   QUIC_ADDRESS_FAMILY_UNSPEC,
                                                   Target, UDP_PORT))) {
    printf("ConnectionStart failed, 0x%x!\n", Status);
    goto Error;
  }

Error:

  if (QUIC_FAILED(Status) && Connection != NULL) {
    MsQuic->ConnectionClose(Connection);
  }
}
