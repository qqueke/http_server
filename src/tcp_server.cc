#include "tcp_server.h"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>

#include "http2_frame_handler.h"
#include "log.h"
#include "tls_manager.h"
#include "utils.h"

extern bool shouldShutdown;

static std::string threadSafeStrerror(int errnum) {
  // std::lock_guard<std::mutex> lock(strerrorMutex);
  return {strerror(errnum)};
}

TcpServer::TcpServer(const std::shared_ptr<Router> &router)
    : router_(router), socket_(-1), socket_addr_(nullptr) {
  struct addrinfo hints{};
  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET6; /*  IPv6 and IPv4 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
  hints.ai_protocol = 0;       /* Any protocol */
  hints.ai_canonname = nullptr;
  hints.ai_addr = nullptr;
  hints.ai_next = nullptr;

  std::string port = std::to_string(HTTP_PORT);

  int s = getaddrinfo(nullptr, port.c_str(), &hints, &socket_addr_);
  if (s != 0) {
    LogError("getaddrinfo: " + std::string(gai_strerror(s)));
    exit(EXIT_FAILURE);
  }

  struct addrinfo *addr = nullptr;
  for (addr = socket_addr_; addr != nullptr; addr = addr->ai_next) {
    socket_ = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (socket_ == -1) {
      continue;
    }

    if (bind(socket_, addr->ai_addr, addr->ai_addrlen) == 0) {
      break;
    }

    close(socket_);
  }

  freeaddrinfo(socket_addr_);

  if (addr == nullptr) {
    LogError("Could not bind to any address");
    exit(EXIT_FAILURE);
  }

  struct timeval timeout{};
  timeout.tv_sec = TIMEOUT_SECONDS;

  int buffSize = 4 * 256 * 1024;
  if (setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) ==
      ERROR) {
    LogError("Failed to set socket recv timeout");
  }
  if (setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, &buffSize, sizeof(buffSize)) ==
      ERROR) {
    LogError("Failed to set socket send timeout");
  }

  codec_ = std::make_shared<HpackCodec>();

  transport_ = std::make_shared<TcpTransport>();

  frame_builder_ = std::make_shared<Http2FrameBuilder>();

  tls_manager_ = std::make_unique<TlsManager>(TlsMode::SERVER, 10);

  (void)tls_manager_->LoadCertificates("certificates/server.crt",
                                       "certificates/server.key");
}

TcpServer::~TcpServer() {
  while (socket_ != -1) {
  }
}

void TcpServer::Run() { AcceptConnections(); }

void TcpServer::AcceptConnections() {
  if (listen(socket_, MAX_PENDING_CONNECTIONS) == ERROR) {
    LogError(threadSafeStrerror(errno));
    return;
  }

  struct timeval timeout{};
  timeout.tv_usec = 100 * 1000;

  int buffSize = 256 * 1024; // 256 KB

  struct pollfd pollFds(socket_, POLLIN, 0);

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

    int client_socket = accept(socket_, (sockaddr *)&peerAddr, &peerAddrLen);
    if (client_socket == ERROR) {
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

    if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    std::thread([this, client_socket]() {
      HandleRequest(client_socket);
    }).detach();
  }

  if (socket_ != -1) {
    close(socket_);
  }

  socket_ = -1;
}

void TcpServer::HandleRequest(int client_socket) {
  SSL *ssl = tls_manager_->CreateSSL(client_socket);
  if (ssl == nullptr) {
    return;
  }

  int ret = tls_manager_->Handshake(ssl, client_socket);
  if (ret == ERROR) {
    return;
  }

  std::string_view protocol = tls_manager_->GetSelectedProtocol(ssl);
  if (protocol == "h2") {
    HandleHTTP2Request(ssl);
  } else if (protocol == "http/1.1") {
    HandleHTTP1Request(ssl);
  } else {
    LogError("Unsupported protocol or ALPN negotiation failed");
  }

  tls_manager_->DeleteSSL(ssl);
  close(client_socket);
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

    ssize_t n_bytes_recv = SSL_read(ssl, buffer.data(), BUFFER_SIZE);

    if (n_bytes_recv == 0) {
      LogError("Client closed the connection");
      break;
    } else if (n_bytes_recv < 0) {
      LogError("Failed to receive data");
      break;
    }

    request.append(buffer.data(), n_bytes_recv);

    while (n_bytes_recv == BUFFER_SIZE && !shouldShutdown) {
      if (SSL_pending(ssl) == 0) {
        LogError("No more data to read");
        break;
      }

      n_bytes_recv = SSL_read(ssl, buffer.data(), BUFFER_SIZE);
      request.append(buffer.data(), n_bytes_recv);
    }

    std::cout << "HTTP1 Request:\n" << request << std::endl;

    std::string body;
    bool accept_enc = false;

    // ValidateHeadersTmp(request, method, path, body, accept_enc);

    auto [headers, resBody] = router_.lock()->RouteRequest(method, path, body);

    static constexpr std::string_view altSvcHeader =
        "Alt-Svc: h3=\":4567\"; ma=86400\r\n";

    size_t headerEnd = headers.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
      headers.insert(headerEnd + 2, altSvcHeader);
    }

    std::string response = headers + resBody;

    std::vector<uint8_t> responseBytes(response.begin(), response.end());
    transport_->Send(ssl, responseBytes);
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

  std::unique_ptr<Http2FrameHandler> frame_handler =
      std::make_unique<Http2FrameHandler>(transport_, frame_builder_, codec_,
                                          router_.lock(), buffer);

  bool receivedPreface = false;

  bool goAway = false;

  int read_offset = 0;
  int write_offset = 0;
  size_t n_readable_bytes = 0;

  // TODO: implement circular buffer

  while (!shouldShutdown && !goAway) {
    int n_bytes_recv = transport_->Read(ssl, buffer, write_offset);
    if (n_bytes_recv == ERROR) {
      break;
    }

    write_offset += n_bytes_recv;
    n_readable_bytes += (size_t)n_bytes_recv;

    if (!receivedPreface) {
      if (n_readable_bytes < PREFACE_LENGTH) {
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

      transport_->Send(ssl, frame_builder_->BuildFrame(Frame::SETTINGS));

      receivedPreface = true;
      read_offset = PREFACE_LENGTH;
      n_readable_bytes -= PREFACE_LENGTH;
    }

    // If we received atleast the frame header
    while (FRAME_HEADER_LENGTH <= n_readable_bytes && !goAway) {
      uint8_t *framePtr = buffer.data() + read_offset;

      uint32_t payload_size = (static_cast<uint32_t>(framePtr[0]) << 16) |
                              (static_cast<uint32_t>(framePtr[1]) << 8) |
                              static_cast<uint32_t>(framePtr[2]);

      if (payload_size > MAX_PAYLOAD_FRAME_SIZE) {
        goAway = true;
        transport_->Send(
            ssl, frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                            HTTP2ErrorCode::FRAME_SIZE_ERROR));
        break;
      }

      uint8_t frame_type = framePtr[3];

      uint8_t frame_flags = framePtr[4];

      uint32_t frame_stream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                              (framePtr[7] << 8) | framePtr[8];

      if (frame_handler->ProcessFrame(nullptr, frame_type, frame_stream,
                                      read_offset, payload_size, frame_flags,
                                      ssl) == ERROR) {
        goAway = true;
        break;
      }

      // Move the offset to the next frame
      read_offset += (int)FRAME_HEADER_LENGTH + payload_size;

      // Decrement readably bytes by the current frame size
      n_readable_bytes -= (size_t)FRAME_HEADER_LENGTH + payload_size;
    }

    if (n_readable_bytes == 0) {
      write_offset = 0;
      read_offset = 0;
    }
  }

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
