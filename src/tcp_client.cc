// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/tcp_client.h"

#include <netdb.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../include/http2_request_handler.h"
#include "../include/log.h"
#include "../include/utils.h"
#include "../lib/ls-hpack/lshpack.h"

TcpClient::TcpClient(
    int argc, char *argv[],
    const std::vector<std::pair<std::string, std::string>> &requests)
    : socket_(-1), socket_addr_(nullptr), requests_(requests) {
  struct addrinfo hints{};
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0; /* Any protocol */

  // struct timeval timeout{};

  std::string target_port = std::to_string(HTTP_PORT);
  std::string target_addr = GetValue2(argc, argv, "target");

  if (target_addr == "") {
    std::cout
        << "No target specified (-target:addr). Defaulting to localhost\n";
    target_addr = "127.0.0.1";
  }

  // Should accept both names and IP addresses
  int s = getaddrinfo(target_addr.c_str(), target_port.c_str(), &hints,
                      &socket_addr_);
  if (s != 0) {
    LogError("getaddrinfo: " + std::string(gai_strerror(s)));
    exit(EXIT_FAILURE);
  }

  codec_ = std::make_shared<HpackCodec>();

  transport_ = std::make_shared<TcpTransport>();

  frame_builder_ = std::make_shared<Http2FrameBuilder>();

  // Instead of giving mode give argc argv and extract modes
  tls_manager_ = std::make_unique<TlsManager>(TlsMode::CLIENT, 10);
}

TcpClient::~TcpClient() { freeaddrinfo(socket_addr_); }

void TcpClient::Run() {
  struct timeval timeout{};
  timeout.tv_usec = 100 * 1000;
  static constexpr int buffSize = 256 * 1024;

  struct addrinfo *addr = nullptr;
  for (addr = socket_addr_; addr != nullptr; addr = addr->ai_next) {
    socket_ = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (socket_ == -1) {
      continue;
    }

    if (setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) == ERROR) {
      LogError("Failed to set socket recv timeout");
    }
    if (setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == ERROR) {
      LogError("Failed to set socket send timeout");
    }

    if (setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError("Failed to set socket recv timeout");
    }
    if (setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError("Failed to set socket send timeout");
    }

    if (connect(socket_, addr->ai_addr, addr->ai_addrlen) == 0) {
      break;
    }

    close(socket_);
  }

  if (addr == nullptr) {
    LogError("Could not connect to any address");
    return;
  }

  SSL *ssl = tls_manager_->CreateSSL(socket_);
  if (ssl == nullptr) {
    return;
  }

  int ret = tls_manager_->Handshake(ssl, socket_);
  if (ret == ERROR) {
    return;
  }

  std::string_view protocol = tls_manager_->GetSelectedProtocol(ssl);
  if (protocol == "h2") {
    SendHttp2Request(ssl);
  } else if (protocol == "http/1.1") {
    SendHttp1Request(ssl);
  } else {
    LogError("Unsupported protocol or ALPN negotiation failed");
  }

  tls_manager_->DeleteSSL(ssl);
  close(socket_);
}

void TcpClient::RecvHttp1Response(SSL *ssl, std::mutex &conn_mutex) {
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

  while (keep_alive) {
    keep_alive = false;
    int n_bytes_recv = transport_->Recv(ssl, buffer, write_offset, conn_mutex);
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

          std::cout << "HTTP1 Response:\n";
          std::cout << headers << "\n" << body << std::endl;

          read_offset += n_readable_bytes;
          headers_map.clear();
        }
        break;
      } else if (buffer[(i + 0) % buffer.size()] == '\r' &&
                 buffer[(i + 1) % buffer.size()] == '\n' &&
                 buffer[(i + 2) % buffer.size()] == '\r' &&
                 buffer[(i + 3) % buffer.size()] == '\n') {
        if (i % buffer.size() < static_cast<unsigned int>(read_offset)) {
          headers = std::string(&buffer[read_offset], &buffer[buffer.size()]);
          headers += std::string(&buffer[0], &buffer[i % buffer.size()]);
        } else {
          headers = std::string(&buffer[read_offset], &buffer[i]);
        }

        headers_map = header_parser.ConvertRequestToPseudoHeaders(
            std::string_view(headers));

        read_offset = i + 4;
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
          std::cout << "Not expecting content-length\n";
          std::cout << "HTTP1 Response:\n";
          std::cout << headers << "\n" << body << std::endl;

          headers_map.clear();
          break;
        }

        // Body is already available
        if (static_cast<long int>(n_readable_bytes) ==
            std::stol(headers_map["content-length"])) {
          uint32_t end_read_offset =
              (read_offset + n_readable_bytes) % buffer.size();

          if (end_read_offset < read_offset) {
            body = std::string(&buffer[read_offset], &buffer[buffer.size()]);
            body += std::string(&buffer[0], &buffer[end_read_offset]);
          } else {
            body = std::string(&buffer[read_offset], &buffer[end_read_offset]);
          }

          std::cout << "HTTP1 Response:\n";
          std::cout << headers << "\n" << body << std::endl;

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

void TcpClient::RecvHttp2Response(SSL *ssl, std::mutex &conn_mutex) {
  std::vector<uint8_t> buffer(65535);

  std::unique_ptr<Http2RequestHandler> request_handler =
      std::make_unique<Http2RequestHandler>(buffer, transport_, frame_builder_,
                                          codec_);

  bool go_away = false;
  uint32_t read_offset = 0;
  uint32_t write_offset = 0;
  size_t n_readable_bytes = 0;

  auto startTime = std::chrono::high_resolution_clock::now();

  while (!go_away) {
    int n_bytes_recv = transport_->Recv(ssl, buffer, write_offset, conn_mutex);
    if (n_bytes_recv == ERROR) {
      break;
    }

    write_offset = (write_offset + n_bytes_recv) % buffer.size();
    n_readable_bytes += static_cast<size_t>(n_bytes_recv);

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

      if (request_handler->ProcessFrame_TS(nullptr, frame_type, frame_stream,
                                         read_offset, payload_size, frame_flags,
                                         ssl, conn_mutex) == ERROR) {
        go_away = true;
        break;
      }

      // Move the offset to the next frame
      read_offset = (read_offset + payload_size) % buffer.size();

      // Decrement readably bytes by the current frame size
      n_readable_bytes -=
          static_cast<size_t>(FRAME_HEADER_LENGTH + payload_size);
    }

    if (n_readable_bytes == 0) {
      write_offset = 0;
      read_offset = 0;
    }
  }

  auto endTime = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> elapsed = endTime - startTime;

  std::cout << "Elapsed time: " << elapsed.count() << " s\n";
}

void TcpClient::SendHttp2Request(SSL *ssl) {
  struct lshpack_enc enc{};
  lshpack_enc_init(&enc);

  std::mutex conn_mutex;
  // Send Preface, Window and SETTINGS
  std::vector<uint8_t> HTTP2_PrefaceBytes = {
      0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32,
      0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A};

  std::vector<uint8_t> frame;
  frame.reserve(FRAME_HEADER_LENGTH + 256);

  std::thread recv_thread(std::bind(&TcpClient::RecvHttp2Response, this, ssl,
                                    std::ref(conn_mutex)));

  transport_->Send(ssl, HTTP2_PrefaceBytes, conn_mutex);

  uint32_t stream_id = 1;

  HeaderParser parser;

  for (const auto &request : requests_) {
    // const auto &request = requests[0];
    const std::string &headers = request.first;
    const std::string &body = request.second;

    std::unordered_map<std::string, std::string> headers_map =
        parser.ConvertRequestToPseudoHeaders(headers);

    // Loop around here
    std::vector<uint8_t> encoded_headers(1024);

    codec_->Encode(&enc, headers_map, encoded_headers);

    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);

    frames.emplace_back(frame_builder_->BuildFrame(Frame::HEADERS, 0, stream_id,
                                                   0, 0, encoded_headers));

    frames.emplace_back(
        frame_builder_->BuildFrame(Frame::DATA, 0, stream_id, 0, 0, {}, body));

    transport_->SendBatch(ssl, frames, conn_mutex);
    stream_id += 2;
  }

  transport_->Send(
      ssl,
      frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0, HTTP2ErrorCode::NO_ERROR),
      conn_mutex);

  recv_thread.join();

  lshpack_enc_cleanup(&enc);
}

void TcpClient::SendHttp1Request(SSL *ssl) {
  std::mutex conn_mutex;
  std::thread recv_thread(std::bind(&TcpClient::RecvHttp1Response, this, ssl,
                                    std::ref(conn_mutex)));
  for (auto &[headers, body] : requests_) {
    std::string request = headers + "\r\n" + body;
    std::cout << "Sending: " << request << std::endl;

    transport_->Send(static_cast<void *>(ssl),
                     static_cast<void *>(request.data()), request.size(),
                     conn_mutex);
  }

  recv_thread.join();
}
