#include "../include/tcp_client.h"

#include <netdb.h>

#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../include/http2_frame_handler.h"
#include "../include/log.h"
#include "../include/utils.h"
#include "../lib/ls-hpack/lshpack.h"

TcpClient::TcpClient(
    int argc, char *argv[],
    const std::vector<std::pair<std::string, std::string>> &requests)
    : requests_(requests), socket_(-1), socket_addr_(nullptr) {
  struct addrinfo hints{};
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0; /* Any protocol */

  struct timeval timeout{};

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

TcpClient::~TcpClient() {}

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

    // Handle errors here
    (void)setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                     sizeof timeout);
    (void)setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof timeout);

    (void)setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &buffSize,
                     sizeof(buffSize));
    (void)setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, &buffSize,
                     sizeof(buffSize));

    if (connect(socket_, addr->ai_addr, addr->ai_addrlen) == 0) {
      break;
    }

    close(socket_);
  }

  freeaddrinfo(socket_addr_);

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

void TcpClient::RecvHttp2Response(SSL *ssl, std::mutex &conn_mutex) {
  std::vector<uint8_t> buffer;
  buffer.reserve(65535);

  std::unique_ptr<Http2FrameHandler> frame_handler =
      std::make_unique<Http2FrameHandler>(buffer, transport_, frame_builder_,
                                          codec_);

  bool goAway = false;
  int read_offset = 0;
  int write_offset = 0;
  size_t n_readable_bytes = 0;

  while (!goAway) {
    int n_bytes_recv = transport_->Read(ssl, buffer, write_offset, conn_mutex);
    if (n_bytes_recv == ERROR) {
      break;
    }

    write_offset += n_bytes_recv;
    n_readable_bytes += static_cast<size_t>(n_bytes_recv);

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

      if (frame_handler->ProcessFrame_TS(nullptr, frame_type, frame_stream,
                                         read_offset, payload_size, frame_flags,
                                         ssl, conn_mutex) == ERROR) {
        goAway = true;
        break;
      }

      // Move the offset to the next frame
      read_offset += static_cast<int>(FRAME_HEADER_LENGTH + payload_size);

      // Decrement readably bytes by the current frame size
      n_readable_bytes -=
          static_cast<size_t>(FRAME_HEADER_LENGTH + payload_size);
    }

    if (n_readable_bytes == 0) {
      write_offset = 0;
      read_offset = 0;
    }
  }
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
  // std::thread recvThread(&HttpClient::HTTP2_RecvFrames_TS, this, ssl);

  transport_->Send(ssl, HTTP2_PrefaceBytes, conn_mutex);

  uint32_t numRequests = 0;
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
    std::vector<uint8_t> frame = frame_builder_->BuildFrame(
        Frame::HEADERS, 0, stream_id, 0, 0, encoded_headers);

    frames.emplace_back(frame);
    frame =
        frame_builder_->BuildFrame(Frame::DATA, 0, stream_id, 0, 0, {}, body);

    frames.emplace_back(frame);

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
  std::cout << "Opsie that is not available...\n";
}
