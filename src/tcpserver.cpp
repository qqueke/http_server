#include "tcpserver.hpp"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>

#include "log.hpp"
#include "server.hpp"
#include "tlsmanager.hpp"
#include "utils.hpp"

extern bool shouldShutdown;

static std::string threadSafeStrerror(int errnum) {
  // std::lock_guard<std::mutex> lock(strerrorMutex);
  return {strerror(errnum)};
}

TcpServer::TcpServer(const std::shared_ptr<Router> &router) : router(router) {
  struct addrinfo hints{};
  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET6; /*  IPv6 and IPv4 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
  hints.ai_protocol = 0;       /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  std::string port = std::to_string(HTTP_PORT);

  int s = getaddrinfo(NULL, port.c_str(), &hints, &tcpSocketAddr);
  if (s != 0) {
    LogError("getaddrinfo: " + std::string(gai_strerror(s)));
    exit(EXIT_FAILURE);
  }

  struct addrinfo *addr = nullptr;
  for (addr = tcpSocketAddr; addr != nullptr; addr = addr->ai_next) {
    tcpSocket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (tcpSocket == -1) {
      continue;
    }

    if (bind(tcpSocket, addr->ai_addr, addr->ai_addrlen) == 0) {
      break;
    }

    close(tcpSocket);
  }

  freeaddrinfo(tcpSocketAddr);

  if (addr == nullptr) {
    LogError("Could not bind to any address");
    exit(EXIT_FAILURE);
  }

  struct timeval timeout{};
  timeout.tv_sec = TIMEOUT_SECONDS;

  int buffSize = 4 * 256 * 1024;
  if (setsockopt(tcpSocket, SOL_SOCKET, SO_RCVBUF, &buffSize,
                 sizeof(buffSize)) == ERROR) {
    LogError("Failed to set socket recv timeout");
  }
  if (setsockopt(tcpSocket, SOL_SOCKET, SO_SNDBUF, &buffSize,
                 sizeof(buffSize)) == ERROR) {
    LogError("Failed to set socket send timeout");
  }

  codec = std::make_shared<HpackCodec>();

  transport = std::make_shared<TcpTransport>();

  frameBuilder = std::make_shared<Http2FrameBuilder>();

  tlsManager = std::make_unique<TlsManager>(TlsMode::SERVER, 10);

  (void)tlsManager->LoadCertificates("certificates/server.crt",
                                     "certificates/server.key");
}

TcpServer::~TcpServer() {
  while (tcpSocket != -1) {
  }
}

void TcpServer::Run() {
  if (frameHandler == nullptr) {
    frameHandler = std::make_unique<Http2ServerFrameHandler>(
        transport, frameBuilder, codec, router.lock());
  }
  AcceptConnections();
}

void TcpServer::AcceptConnections() {
  if (listen(tcpSocket, MAX_PENDING_CONNECTIONS) == ERROR) {
    LogError(threadSafeStrerror(errno));
    return;
  }

  struct timeval timeout{};
  timeout.tv_usec = 100 * 1000;

  int buffSize = 256 * 1024; // 256 KB

  struct pollfd pollFds(tcpSocket, POLLIN, 0);

  while (!shouldShutdown) {
    int polling = poll(&pollFds, 1, 1 * 1000);
    if (polling == 0) {
      continue;
    } else if (polling == ERROR) {
      LogError("Poll error on main thread");
      continue;
    }

    sockaddr clientAddr{};
    socklen_t len = sizeof(clientAddr);

    struct sockaddr_storage peerAddr;
    socklen_t peerAddrLen = sizeof(peerAddr);

    int clientSocket = accept(tcpSocket, (sockaddr *)&peerAddr, &peerAddrLen);
    if (clientSocket == ERROR) {
      LogError(threadSafeStrerror(errno));
      continue;
    }

    if (peerAddr.ss_family == AF_INET) { // IPv4
      sockaddr_in *ipv4 = (struct sockaddr_in *)&peerAddr;
      char ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
      std::cout << "Connection established with IPv4 address: " << ip
                << std::endl;
    } else if (peerAddr.ss_family == AF_INET6) { // IPv6
      sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&peerAddr;
      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
      std::cout << "Connection established with IPv6 address: " << ip
                << std::endl;
    } else {
      std::cout << "Unknown address family: " << peerAddr.ss_family
                << std::endl;
    }

    if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(tcpSocket, SOL_SOCKET, SO_RCVBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(tcpSocket, SOL_SOCKET, SO_SNDBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    std::thread([this, clientSocket]() {
      HandleRequest(clientSocket);
    }).detach();
  }

  if (tcpSocket != -1) {
    close(tcpSocket);
  }

  tcpSocket = -1;
}

void TcpServer::HandleRequest(int clientSocket) {
  SSL *ssl = tlsManager->CreateSSL(clientSocket);
  if (ssl == nullptr) {
    return;
  }

  int ret = tlsManager->Handshake(ssl, clientSocket);
  if (ret == ERROR) {
    return;
  }

  std::string_view protocol = tlsManager->GetSelectedProtocol(ssl);
  if (protocol == "h2") {
    HandleHTTP2Request(ssl);
  } else if (protocol == "http/1.1") {
    HandleHTTP1Request(ssl);
  } else {
    LogError("Unsupported protocol or ALPN negotiation failed");
  }

  tlsManager->DeleteSSL(ssl);
  close(clientSocket);
}

void TcpServer::HandleHTTP1Request(SSL *ssl) {
  auto startTime = std::chrono::high_resolution_clock::now();
  std::array<char, BUFFER_SIZE> buffer{};
  std::string request;

  std::string method{};
  std::string path{};
  std::string status{};

  // Just to not delete the while loop
  bool keepAlive = true;

  while (!shouldShutdown && keepAlive) {
    keepAlive = false;

    ssize_t bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);

    if (bytesReceived == 0) {
      LogError("Client closed the connection");
      break;
    } else if (bytesReceived < 0) {
      LogError("Failed to receive data");
      break;
    }

    request.append(buffer.data(), bytesReceived);

    while (bytesReceived == BUFFER_SIZE && !shouldShutdown) {
      if (SSL_pending(ssl) == 0) {
        LogError("No more data to read");
        break;
      }

      bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);
      request.append(buffer.data(), bytesReceived);
    }

    std::cout << "HTTP1 Request:\n" << request << std::endl;

    std::string body;
    bool acceptEncoding = false;

    // ValidateHeadersTmp(request, method, path, body, acceptEncoding);

    auto [headers, resBody] = router.lock()->RouteRequest(method, path, body);

    static constexpr std::string_view altSvcHeader =
        "Alt-Svc: h3=\":4567\"; ma=86400\r\n";

    size_t headerEnd = headers.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
      headers.insert(headerEnd + 2, altSvcHeader);
    }

    std::string response = headers + resBody;

    std::vector<uint8_t> responseBytes(response.begin(), response.end());
    transport->Send(ssl, responseBytes);
  }

  // Timer should end  here and log it to the file
  auto endTime = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> elapsed = endTime - startTime;

  std::ostringstream logStream;
  logStream << "Protocol: HTTP1 "
            << "Method: " << method << " Path: " << path
            << " Status: " << status << " Elapsed time: " << elapsed.count()
            << " s";

  LogRequest(logStream.str());
}

void TcpServer::HandleHTTP2Request(SSL *ssl) {
  static constexpr std::array<uint8_t, 24> HTTP2_PrefaceBytes = {
      0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32,
      0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A};

  std::vector<uint8_t> buffer;
  buffer.reserve(65535);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      decodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> encodedHeadersBufferMap;

  std::unordered_map<uint32_t, std::string> dataMap;

  struct lshpack_enc enc{};
  lshpack_enc_init(&enc);

  struct lshpack_dec dec{};
  lshpack_dec_init(&dec);

  // auto startTime = std::chrono::high_resolution_clock::now();

  uint32_t connWindowSize{};
  std::unordered_map<uint32_t, uint32_t> strmWindowSizeMap;

  bool expectingContFrame = false;

  Http2FrameContext context(buffer, decodedHeadersMap, encodedHeadersBufferMap,
                            dataMap, enc, dec, connWindowSize,
                            strmWindowSizeMap, expectingContFrame);

  bool receivedPreface = false;

  bool goAway = false;
  uint32_t nRequests = 0;

  int readOffset = 0;
  int writeOffset = 0;
  size_t nReadableBytes = 0;

  // TODO: implement circular buffer

  while (!shouldShutdown && !goAway) {
    int bytesReceived = transport->Read(ssl, buffer, writeOffset);
    if (bytesReceived == ERROR) {
      break;
    }

    writeOffset += bytesReceived;
    nReadableBytes += (size_t)bytesReceived;

    if (!receivedPreface) {
      if (nReadableBytes < PREFACE_LENGTH) {
        continue;
      }

      if (memcmp(HTTP2_PrefaceBytes.data(), buffer.data(), PREFACE_LENGTH) !=
          0) {
        LogError("Invalid HTTP/2 preface, closing connection.");
        break;
      }

#ifdef HTTP2_DEBUG
      std::cout << "HTTP/2 Connection Preface received!\n";
#endif

      transport->Send(ssl, frameBuilder->BuildFrame(Frame::SETTINGS));

      receivedPreface = true;
      readOffset = PREFACE_LENGTH;
      nReadableBytes -= PREFACE_LENGTH;
    }

    // If we received atleast the frame header
    while (FRAME_HEADER_LENGTH <= nReadableBytes && !goAway) {
      uint8_t *framePtr = buffer.data() + readOffset;

      uint32_t payloadLength = (static_cast<uint32_t>(framePtr[0]) << 16) |
                               (static_cast<uint32_t>(framePtr[1]) << 8) |
                               static_cast<uint32_t>(framePtr[2]);

      if (payloadLength > MAX_PAYLOAD_FRAME_SIZE) {
        goAway = true;
        transport->Send(
            ssl, frameBuilder->BuildFrame(Frame::GOAWAY, 0, 0,
                                          HTTP2ErrorCode::FRAME_SIZE_ERROR));
        break;
      }

      uint8_t frameType = framePtr[3];

      uint8_t frameFlags = framePtr[4];

      uint32_t frameStream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                             (framePtr[7] << 8) | framePtr[8];

      if (expectingContFrame && frameType != Frame::CONTINUATION) {
        goAway = true;
        transport->Send(
            ssl, frameBuilder->BuildFrame(Frame::GOAWAY, 0, 0,
                                          HTTP2ErrorCode::PROTOCOL_ERROR));
        break;
      }

      if (frameHandler->ProcessFrame(&context, frameType, frameStream,
                                     readOffset, payloadLength, frameFlags,
                                     ssl) == ERROR) {
        goAway = true;
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

  lshpack_enc_cleanup(&enc);
  lshpack_dec_cleanup(&dec);

  // Timer should end  here and log it to the file
  // auto endTime = std::chrono::high_resolution_clock::now();

  // std::chrono::duration<double> elapsed = endTime - startTime;

  // std::cout << "Elapsed time: " << elapsed.count() << " s" << std::endl;

  // std::ostringstream logStream;
  // logStream << "Protocol: HTTP2 "
  //           << "Method: " << method << " Path: " << path
  //           << " Status: " << status << " Elapsed time: " << elapsed.count()
  //           << " s";
  //
  // LogRequest(logStream.str());
}
