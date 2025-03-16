// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/tcp_server.h"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../include/http2_frame_handler.h"
#include "../include/log.h"
#include "../include/tls_manager.h"
#include "../include/utils.h"

// #define ECHO
extern bool shouldShutdown;

static std::string threadSafeStrerror(int errnum) {
  // std::lock_guard<std::mutex> lock(strerrorMutex);
  return {strerror(errnum)};
}

TcpServer::TcpServer(
    const std::shared_ptr<Router> &router,
    const std::shared_ptr<StaticContentHandler> &content_handler)
    : router_(router),
      static_content_handler_(content_handler),
      socket_(-1),
      socket_addr_(nullptr) {
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

  if (setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ==
      ERROR) {
    LogError("Failed to set socket recv timeout");
  }
  if (setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
      ERROR) {
    LogError("Failed to set socket send timeout");
  }

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

  int buffSize = 256 * 1024;

  struct pollfd pollFds(socket_, POLLIN, 0);

  while (!shouldShutdown) {
    int polling = poll(&pollFds, 1, 1 * 1000);
    if (polling == 0) {
      continue;
    } else if (polling == ERROR) {
      LogError("Poll error on main thread");
      continue;
    }

    struct sockaddr_storage peerAddr;
    socklen_t peerAddrLen = sizeof(peerAddr);

    int client_socket =
        accept(socket_, reinterpret_cast<sockaddr *>(&peerAddr), &peerAddrLen);
    if (client_socket == ERROR) {
      LogError(threadSafeStrerror(errno));
      continue;
    }

    // if (peerAddr.ss_family == AF_INET) { // IPv4
    //   sockaddr_in *ipv4 = (struct sockaddr_in *)&peerAddr;
    //   char ip[INET_ADDRSTRLEN];
    //   inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
    //   std::cout << "Connection established with IPv4 address: " << ip
    //             << std::endl;
    // } else if (peerAddr.ss_family == AF_INET6) { // IPv6
    //   sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&peerAddr;
    //   char ip[INET6_ADDRSTRLEN];
    //   inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
    //   std::cout << "Connection established with IPv6 address: " << ip
    //             << std::endl;
    // } else {
    //   std::cout << "Unknown address family: " << peerAddr.ss_family
    //             << std::endl;
    // }

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
  std::string headers{};
  std::string body{};
  std::unordered_map<std::string, std::string> headers_map{};
  // Just to not delete the while loop
  bool keep_alive = true;
  std::vector<uint8_t> buffer(65535);

  uint32_t read_offset = 0;
  uint32_t write_offset = 0;
  size_t n_readable_bytes = 0;

  HeaderParser header_parser;

  while (!shouldShutdown && keep_alive) {
    keep_alive = false;
    int n_bytes_recv = transport_->Read(ssl, buffer, write_offset);
    if (n_bytes_recv <= 0) {
      break;
    }
    write_offset = (write_offset + n_bytes_recv) % buffer.size();

    n_readable_bytes += static_cast<size_t>(n_bytes_recv);

    for (size_t i = read_offset; i < n_readable_bytes - 3; ++i) {
      if (!headers_map.empty()) {
        // Body is already available
        if (static_cast<int64_t>(n_readable_bytes) ==
            std::stol(headers_map["content-length"])) {
          uint32_t end_read_offset =
              (read_offset + n_readable_bytes) % buffer.size();

          if (end_read_offset < read_offset) {
            body = std::string(&buffer[read_offset], &buffer[buffer.size()]);
            body += std::string(&buffer[0], &buffer[end_read_offset]);
          } else {
            body = std::string(&buffer[read_offset],
                               &buffer[read_offset + n_readable_bytes]);
          }

#ifdef ECHO
          std::cout << "HTTP1 Request:\n";
          std::cout << headers << "\n" << body << std::endl;
#endif

          auto [res_headers, res_body] = router_.lock()->RouteRequest(
              headers_map[":method"], headers_map[":path"], body);

          std::string res = res_headers + res_body;

          transport_->Send(static_cast<void *>(ssl),
                           static_cast<void *>(res.data()), res.size());

          read_offset += n_readable_bytes;
          headers_map.clear();
        }
        break;
      } else if (buffer[(i + 0) % buffer.size()] == '\r' &&
                 buffer[(i + 1) % buffer.size()] == '\n' &&
                 buffer[(i + 2) % buffer.size()] == '\r' &&
                 buffer[(i + 3) % buffer.size()] == '\n') {
        if (i % buffer.size() < static_cast<size_t>(read_offset)) {
          headers = std::string(&buffer[read_offset], &buffer[buffer.size()]);
          headers += std::string(&buffer[0], &buffer[i % buffer.size()]);
        } else {
          headers = std::string(&buffer[read_offset], &buffer[i]);
        }

        // Maybe we could just parse the headerrs instead of converting to
        // pseudo headers but the bottleneck is still there for the handshakes
        // and all
        headers_map = header_parser.ConvertRequestToPseudoHeaders(
            std::string_view(headers));

        read_offset = (i + 4) % buffer.size();
        n_readable_bytes -= headers.size() + 4;

        if (headers_map.find("keep-alive") != headers_map.end()) {
          keep_alive = true;
        }

        if (headers_map.find("connection") != headers_map.end() &&
            headers_map["connection"] == "close") {
          keep_alive = false;
        }

        // Not expecting body so we route and answer
        if (headers_map.find("content-length") == headers_map.end()) {
#ifdef ECHO
          std::cout << "HTTP1 Request:\n";
          std::cout << headers << "\n" << body << std::endl;
#endif
          auto [res_headers, res_body] = router_.lock()->RouteRequest(
              headers_map[":method"], headers_map[":path"]);
          std::string res = res_headers + res_body;
          transport_->Send(static_cast<void *>(ssl),
                           static_cast<void *>(res.data()), res.size());
          headers_map.clear();
          break;
        }

        // Body is already available
        if (static_cast<int32_t>(n_readable_bytes) ==
            std::stol(headers_map["content-length"])) {
          uint32_t end_read_offset =
              (read_offset + n_readable_bytes) % buffer.size();

          if (end_read_offset < read_offset) {
            body = std::string(&buffer[read_offset], &buffer[buffer.size()]);
            body += std::string(&buffer[0], &buffer[end_read_offset]);
          } else {
            body = std::string(&buffer[read_offset], &buffer[end_read_offset]);
          }

#ifdef ECHO
          std::cout << "HTTP1 Request:\n";
          std::cout << headers << "\n" << body << std::endl;
#endif
          auto [res_headers, res_body] = router_.lock()->RouteRequest(
              headers_map[":method"], headers_map[":path"], body);

          std::string res = res_headers + res_body;

          transport_->Send(static_cast<void *>(ssl),
                           static_cast<void *>(res.data()), res.size());

          read_offset = (read_offset + n_readable_bytes) % buffer.size();
          headers_map.clear();
        } else {
          std::cout << "Body is not available yet\n";
        }

        break;
      }
    }
  }

  // Timer should end  here and log it to the file
  auto endTime = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> elapsed = endTime - startTime;

  // std::ostringstream logStream;
  // logStream << "Protocol: HTTP1 "
  //           << "Method: " << method << " Path: " << path
  //           << " Status: " << status << " Elapsed time: " << elapsed.count()
  //           << " s";
  //
  // LogRequest(logStream.str());
}

void TcpServer::HandleHTTP2Request(SSL *ssl) {
  static constexpr std::array<uint8_t, 24> HTTP2_PrefaceBytes = {
      0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32,
      0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A};

  std::vector<uint8_t> buffer(65535);
  // buffer.reserve(65535);

  std::unique_ptr<Http2FrameHandler> frame_handler =
      std::make_unique<Http2FrameHandler>(buffer, transport_, frame_builder_,
                                          codec_, router_.lock(),
                                          static_content_handler_.lock());

  bool received_preface = false;

  bool go_away = false;

  uint32_t read_offset = 0;
  uint32_t write_offset = 0;
  size_t n_readable_bytes = 0;

  // TODO(QQueke): Implement circular buffer

  while (!shouldShutdown && !go_away) {
    int n_bytes_recv = transport_->Read(ssl, buffer, write_offset);
    if (n_bytes_recv == ERROR) {
      break;
    }

    write_offset = (write_offset + n_bytes_recv) % buffer.size();
    n_readable_bytes += static_cast<size_t>(n_bytes_recv);

    if (!received_preface) {
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

      received_preface = true;
      read_offset = PREFACE_LENGTH;
      n_readable_bytes -= PREFACE_LENGTH;
    }

    // If we received atleast the frame header
    while (FRAME_HEADER_LENGTH <= n_readable_bytes && !go_away) {
      uint32_t payload_size =
          (static_cast<uint32_t>(buffer[(read_offset + 0) % buffer.size()])
           << 16) |
          (static_cast<uint32_t>(buffer[(read_offset + 1) % buffer.size()])
           << 8) |
          static_cast<uint32_t>(buffer[(read_offset + 2) % buffer.size()]);

      if (payload_size > MAX_PAYLOAD_FRAME_SIZE) {
        go_away = true;
        transport_->Send(
            ssl, frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                            HTTP2ErrorCode::FRAME_SIZE_ERROR));
        break;
      }

      if (payload_size + FRAME_HEADER_LENGTH > n_readable_bytes) {
        // Not ready to process the payloads
        break;
      }

      uint8_t frame_type = buffer[(read_offset + 3) % buffer.size()];

      uint8_t frame_flags = buffer[(read_offset + 4) % buffer.size()];

      uint32_t frame_stream =
          (buffer[(read_offset + 5) % buffer.size()] << 24) |
          (buffer[(read_offset + 6) % buffer.size()] << 16) |
          (buffer[(read_offset + 7) % buffer.size()] << 8) |
          buffer[(read_offset + 8) % buffer.size()];

      read_offset = (read_offset + FRAME_HEADER_LENGTH) % buffer.size();

      if (frame_handler->ProcessFrame(nullptr, frame_type, frame_stream,
                                      read_offset, payload_size, frame_flags,
                                      ssl) == ERROR) {
        go_away = true;
        break;
      }

      // Move the offset to the next frame
      read_offset = (read_offset + payload_size) % buffer.size();

      // Decrement readably bytes by the current frame size
      n_readable_bytes -=
          static_cast<size_t>(FRAME_HEADER_LENGTH + payload_size);
    }

    if (static_cast<int32_t>(n_readable_bytes) == 0) {
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
