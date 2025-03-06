#include "tcp_client.h"

#include <netdb.h>

#include <functional>
#include <iostream>
#include <thread>
#include <vector>

#include "common.h"
#include "log.h"
#include "lshpack.h"
#include "utils.h"

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
  static constexpr int buffSize = 256 * 1024; // 256 KB

  struct addrinfo *addr = nullptr;
  for (addr = socket_addr_; addr != nullptr; addr = addr->ai_next) {
    socket_ = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (socket_ == -1) {
      continue;
    }

    // Handle errors here
    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

    setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize));
    setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, &buffSize, sizeof(buffSize));

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
  struct lshpack_dec dec{};
  lshpack_dec_init(&dec);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      tcp_decoded_headers_map;

  // Buffer for encoded headers until decoding
  std::unordered_map<uint32_t, std::vector<uint8_t>> encoded_headers_buf_map;
  std::unordered_map<uint32_t, std::string> tcp_data_map;

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
  uint8_t retry_count = 0;
  int n_bytes_recv = 0;
  int read_offset = 0;
  int write_offset = 0;
  size_t n_readable_bytes = 0;

  while (!GOAWAY) {
    n_bytes_recv = transport_->Read_TS(ssl, buffer, write_offset, conn_mutex);
    if (n_bytes_recv == ERROR) {
      break;
    }

    write_offset += n_bytes_recv;
    n_readable_bytes += (size_t)n_bytes_recv;

    retry_count = 0;

    // If we received atleast the frame header
    while (FRAME_HEADER_LENGTH <= n_readable_bytes && !GOAWAY) {
      uint8_t *framePtr = buffer.data() + read_offset;

      uint32_t payload_size = (static_cast<uint32_t>(framePtr[0]) << 16) |
                              (static_cast<uint32_t>(framePtr[1]) << 8) |
                              static_cast<uint32_t>(framePtr[2]);

      // if (offset + FRAME_HEADER_LENGTH + payload_size > buffer.size()) {
      //   break;
      // }

      uint8_t frame_type = framePtr[3];

      uint8_t frame_flags = framePtr[4];

      uint32_t frame_stream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                              (framePtr[7] << 8) | framePtr[8];

      if (FRAME_HEADER_LENGTH + payload_size > n_readable_bytes) {
        std::cout << "Not enough data: " << FRAME_HEADER_LENGTH + payload_size
                  << " with readable: " << n_readable_bytes << std::endl;
        break;
      }

      if (expectingContFrame && frame_type != Frame::CONTINUATION) {
        GOAWAY = true;
        transport_->Send_TS(
            ssl,
            frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                       HTTP2ErrorCode::PROTOCOL_ERROR),
            conn_mutex);
        break;
      }

      switch (frame_type) {
      case Frame::DATA:

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream << "] DATA frame\n";
#endif
        tcp_data_map[frame_stream] += std::string(
            reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
            payload_size);

        // std::cout << tcp_data_map[frame_stream] << std::endl;

        if (isFlagSet(frame_flags, END_STREAM_FLAG)) {
          // HTTPServer::ValidatePseudoHeaders(tcp_decoded_headers_map[frame_stream]);

#ifdef ECHO
          std::cout << "Response:\n";
          for (const auto &[key, value] :
               tcp_decoded_headers_map[frame_stream]) {
            std::cout << key << ": " << value << "\n";
          }

          std::cout << tcp_data_map[frame_stream] << "\n";
#endif
          // if (tcp_data_map[frame_stream] != "Bad Request") {
          //   std::cout << " WE HAVE A PROBLEM: " <<
          //   tcp_data_map[frame_stream];
          // }
          // std::cout << std::endl;

          tcp_data_map.erase(frame_stream);
          tcp_decoded_headers_map.erase(frame_stream);
          encoded_headers_buf_map.erase(frame_stream);
          ++nResponses;
        }
        break;
      case Frame::HEADERS:
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream << "] HEADERS frame\n";
#endif

        if (frame_stream == 0) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR),
              conn_mutex);
          break;
        }

        {
          uint8_t *headerBlockStart = framePtr + FRAME_HEADER_LENGTH;
          uint8_t *payloadEnd = headerBlockStart + payload_size;
          uint8_t padLength = 0;

          if (isFlagSet(frame_flags, HTTP2Flags::PADDED_FLAG)) {
            padLength = headerBlockStart[0];
            ++headerBlockStart; // Jump over pad length
          }

          if (isFlagSet(frame_flags, HTTP2Flags::PRIORITY_FLAG)) {
            headerBlockStart += 4; // Jump over stream dependency
            ++headerBlockStart;    // Jump over weight
          }

          uint32_t headerBlockLength =
              payloadEnd - headerBlockStart - padLength;

          if (headerBlockStart + headerBlockLength > payloadEnd) {
            transport_->Send_TS(
                ssl,
                frame_builder_->BuildFrame(Frame::RST_STREAM, 0, frame_stream,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR),
                conn_mutex);
            break;
          }

          // Do we really need to buffer the header blocks?
          encoded_headers_buf_map[frame_stream].insert(
              encoded_headers_buf_map[frame_stream].end(), headerBlockStart,
              headerBlockStart + headerBlockLength);

          if (isFlagSet(frame_flags, END_STREAM_FLAG) &&
              isFlagSet(frame_flags, END_HEADERS_FLAG)) {
            codec_->Decode(&dec, encoded_headers_buf_map[frame_stream],
                           tcp_decoded_headers_map[frame_stream]);

#ifdef ECHO
            std::cout << "Response: \n";
            for (auto &[key, value] : tcp_decoded_headers_map[frame_stream]) {
              std::cout << key << ": " << value << "\n";
            }
            std::cout << tcp_data_map[frame_stream] << std::endl;
#endif
            transport_->Send_TS(ssl,
                                frame_builder_->BuildFrame(Frame::WINDOW_UPDATE,
                                                           0, 0, 0, 65536),
                                conn_mutex);

            ++nRequests;
            tcp_data_map.erase(frame_stream);
            tcp_decoded_headers_map.erase(frame_stream);
            encoded_headers_buf_map.erase(frame_stream);
            break;
          }

          if (isFlagSet(frame_flags, END_HEADERS_FLAG)) {
            codec_->Decode(&dec, encoded_headers_buf_map[frame_stream],
                           tcp_decoded_headers_map[frame_stream]);
          } else {
            expectingContFrame = true;
          }
        }

        break;
      case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream << "] PRIORITY frame\n";
#endif

        break;
      case Frame::RST_STREAM:
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream
                  << "] Received RST_STREAM frame\n";
#endif
        if (frame_stream == 0) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR),
              conn_mutex);
          break;
        } else if (payload_size != 4) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR),
              conn_mutex);
          break;
        }

        {
          uint32_t error = (framePtr[9] << 24) | (framePtr[10] << 16) |
                           (framePtr[11] << 8) | framePtr[12];
        }
        tcp_data_map.erase(frame_stream);
        tcp_decoded_headers_map.erase(frame_stream);
        encoded_headers_buf_map.erase(frame_stream);
        break;

      case Frame::SETTINGS:
#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream << "] SETTINGS frame\n";
#endif
        if (payload_size % 6 != 0) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR),
              conn_mutex);
          break;
        } else if (frame_stream != 0) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR),
              conn_mutex);
          break;
        }

        if (isFlagSet(frame_flags, HTTP2Flags::NONE_FLAG)) {
          // Parse their settings and update this connection settings
          // to be the minimum between ours and theirs

          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::SETTINGS,
                                         HTTP2Flags::SETTINGS_ACK_FLAG),
              conn_mutex);
        } else if (isFlagSet(frame_flags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
          if (payload_size != 0) {
            GOAWAY = true;
            transport_->Send_TS(
                ssl,
                frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR),
                conn_mutex);
            break;
          }
          // Received ACK to our settings
        }

        break;

      case Frame::PING:

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream << "] PING frame\n";
#endif

        // This is used to measure minimal round-trip (useful for graceful
        // shutdown with goaway)

        if (frame_stream != 0) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR),
              conn_mutex);
          break;
        } else if (payload_size != 8) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR),
              conn_mutex);
          break;
        }

        if (!isFlagSet(frame_flags, HTTP2Flags::PING_ACK_FLAG)) {
          {
            if (frame.size() != FRAME_HEADER_LENGTH + payload_size) {
              frame.resize(FRAME_HEADER_LENGTH + payload_size);
            }

            memcpy(frame.data(), framePtr, FRAME_HEADER_LENGTH + payload_size);
            frame[4] = HTTP2Flags::PING_ACK_FLAG;

            transport_->Send_TS(ssl, frame, conn_mutex);
          }
        }

        break;

      case Frame::GOAWAY:

        // std::cout << "[strm][" << frame_stream << "] GOAWAY frame\n";
        GOAWAY = true;

        tcp_data_map.erase(frame_stream);
        tcp_decoded_headers_map.erase(frame_stream);
        encoded_headers_buf_map.erase(frame_stream);
        break;

      case Frame::WINDOW_UPDATE:

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream << "] WINDOW_UPDATE frame\n";
#endif
        {
          uint32_t win_increment = (framePtr[9] << 24) | (framePtr[10] << 16) |
                                   (framePtr[11] << 8) | framePtr[12];

          // std::cout << "Window increment: " << win_increment << "\n";
          if (win_increment == 0) {
            GOAWAY = true;
            transport_->Send_TS(
                ssl,
                frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::PROTOCOL_ERROR),
                conn_mutex);
            break;
          } else if (payload_size != 4) {
            GOAWAY = true;
            transport_->Send_TS(
                ssl,
                frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR),
                conn_mutex);
            break;
          }

          if (frame_stream == 0) {
            connectionWindowSize += win_increment;
            if (connectionWindowSize > MAX_FLOW_WINDOW_SIZE) {
              GOAWAY = true;
              transport_->Send_TS(
                  ssl,
                  frame_builder_->BuildFrame(
                      Frame::GOAWAY, 0, 0, HTTP2ErrorCode::FLOW_CONTROL_ERROR),
                  conn_mutex);
              break;
            }
          } else {
            streamWindowSizeMap[frame_stream] += win_increment;
            if (streamWindowSizeMap[frame_stream] > MAX_FLOW_WINDOW_SIZE) {
              transport_->Send_TS(
                  ssl,
                  frame_builder_->BuildFrame(
                      Frame::GOAWAY, 0, 0, HTTP2ErrorCode::FLOW_CONTROL_ERROR),
                  conn_mutex);
              break;
            }
          }
        }

        break;

      case Frame::CONTINUATION:

#ifdef HTTP2_DEBUG
        std::cout << "[strm][" << frame_stream << "] CONTINUATION frame\n";
#endif
        if (frame_stream == 0) {
          GOAWAY = true;
          transport_->Send_TS(
              ssl,
              frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR),
              conn_mutex);
          break;
        }

        {
          encoded_headers_buf_map[frame_stream].insert(
              encoded_headers_buf_map[frame_stream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payload_size);

          if (isFlagSet(frame_flags, END_STREAM_FLAG) &&
              isFlagSet(frame_flags, END_HEADERS_FLAG)) {
            // Decode and dispatch request
            codec_->Decode(&dec, encoded_headers_buf_map[frame_stream],
                           tcp_decoded_headers_map[frame_stream]);

#ifdef ECHO
            std::cout << "Response:\n";
            for (const auto &[key, value] :
                 tcp_decoded_headers_map[frame_stream]) {
              std::cout << key << ": " << value << "\n";
            }
#endif
            tcp_data_map.erase(frame_stream);
            tcp_decoded_headers_map.erase(frame_stream);
            encoded_headers_buf_map.erase(frame_stream);
            ++nResponses;
            break;
          }

          if (isFlagSet(frame_flags, END_HEADERS_FLAG)) {
            expectingContFrame = false;
            // Decode and wait for request body
            codec_->Decode(&dec, encoded_headers_buf_map[frame_stream],
                           tcp_decoded_headers_map[frame_stream]);
          }
          // Expecting another continuation frame ...
          else {
            expectingContFrame = true;
          }
        }
        break;

      default:
        std::cout << "[strm][" << frame_stream << "] Unknown frame type: 0x"
                  << std::dec << frame_type << std::dec << "\n";
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
  std::cout << "Received: " << nResponses << "\n";

  lshpack_dec_cleanup(&dec);
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

  // std::thread recv_thread(&TcpClient::RecvHttp2Response, this, ssl,
  // conn_mutex);

  std::thread recv_thread(std::bind(&TcpClient::RecvHttp2Response, this, ssl,
                                    std::ref(conn_mutex)));
  // std::thread recvThread(&HttpClient::HTTP2_RecvFrames_TS, this, ssl);

  transport_->Send_TS(ssl, HTTP2_PrefaceBytes, conn_mutex);

  uint32_t numRequests = 0;
  uint32_t stream_id = 1;

  for (const auto &request : requests_) {
    // const auto &request = requests[0];
    const std::string &headers = request.first;
    const std::string &body = request.second;

    std::unordered_map<std::string, std::string> headers_map;

    HttpCore::ReqHeaderToPseudoHeader(headers, headers_map);

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

    transport_->SendBatch_TS(ssl, frames, conn_mutex);
    stream_id += 2;
  }

  transport_->Send_TS(
      ssl,
      frame_builder_->BuildFrame(Frame::GOAWAY, 0, 0, HTTP2ErrorCode::NO_ERROR),
      conn_mutex);

  recv_thread.join();

  lshpack_enc_cleanup(&enc);
}

void TcpClient::SendHttp1Request(SSL *ssl) {
  std::cout << "Opsie that is not available...\n";
}
