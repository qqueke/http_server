#include "http2_frame_handler.h"

#include <iostream>

#include "http2_frame_builder.h"
#include "log.h"
#include "server.h"

#define HTTP2_DEBUG
static void ValidatePseudoHeadersTmp(
    std::unordered_map<std::string, std::string> &headers_map) {
  static constexpr std::array<std::string_view, 3> requiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : requiredHeaders) {
    if (headers_map.find(std::string(header)) == headers_map.end()) {
      // LogError("Failed to validate pseudo-headers (missing header field)");
      headers_map[":method"] = "BR";
      headers_map[":path"] = "";
      return;
    }
  }
}

Http2FrameHandler::Http2FrameHandler(
    const std::shared_ptr<TcpTransport> &tcp_transport,
    const std::shared_ptr<Http2FrameBuilder> &http2_frame_builder,
    const std::shared_ptr<HpackCodec> &hpack_codec,
    const std::shared_ptr<Router> &router, const std::vector<uint8_t> &read_buf)
    : transport_(tcp_transport), frame_builder_(http2_frame_builder),
      codec_(hpack_codec), router_(router), read_buf(read_buf), enc_(), dec_(),
      conn_win_size_(0), wait_for_cont_frame_(false), is_server_(true) {
  lshpack_enc_init(&enc_);
  lshpack_dec_init(&dec_);
}

Http2FrameHandler::Http2FrameHandler(
    const std::shared_ptr<TcpTransport> &tcp_transport,
    const std::shared_ptr<Http2FrameBuilder> &http2_frame_builder,
    const std::shared_ptr<HpackCodec> &hpack_codec,
    const std::vector<uint8_t> &read_buf)
    : transport_(tcp_transport), frame_builder_(http2_frame_builder),
      codec_(hpack_codec), read_buf(read_buf), enc_(), dec_(),
      conn_win_size_(0), wait_for_cont_frame_(false), is_server_(false) {
  lshpack_enc_init(&enc_);
  lshpack_dec_init(&dec_);
}

Http2FrameHandler::~Http2FrameHandler() {
  lshpack_enc_cleanup(&enc_);
  lshpack_dec_cleanup(&dec_);
}

int Http2FrameHandler::ProcessFrame(void *context, uint8_t frame_type,
                                    uint32_t frame_stream, uint32_t read_offset,
                                    uint32_t payload_size, uint8_t frame_flags,
                                    SSL *ssl) {
  if (wait_for_cont_frame_ && frame_type != Frame::CONTINUATION) {
    auto transport_ptr = transport_.lock();
    if (transport_ptr == nullptr) {
      return ERROR;
    }

    auto frame_builder_ptr = frame_builder_.lock();
    if (frame_builder_ptr == nullptr) {
      return ERROR;
    }

    transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  }

  switch (frame_type) {
  case Frame::DATA:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] DATA frame\n";
#endif

    return HandleDataFrame(context, frame_stream, read_offset, payload_size,
                           frame_flags, ssl);
  case Frame::HEADERS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] HEADERS frame\n";
#endif

    return HandleHeadersFrame(context, frame_stream, read_offset, payload_size,
                              frame_flags, ssl);
  case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] PRIORITY frame\n";
#endif

    return HandlePriorityFrame(context, frame_stream, read_offset, payload_size,
                               frame_flags, ssl);
  case Frame::RST_STREAM:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] RST_STREAM frame\n";
#endif

    return HandleRstStreamFrame(context, frame_stream, read_offset,
                                payload_size, frame_flags, ssl);
    break;
  case Frame::SETTINGS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] SETTINGS frame\n";
#endif

    return HandleSettingsFrame(context, frame_stream, read_offset, payload_size,
                               frame_flags, ssl);
  case Frame::PING:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] PING frame\n";
#endif

    return HandlePingFrame(context, frame_stream, read_offset, payload_size,
                           frame_flags, ssl);
  case Frame::GOAWAY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] GOAWAY frame\n";
#endif

    return HandleGoAwayFrame(context, frame_stream, read_offset, payload_size,
                             frame_flags, ssl);
  case Frame::CONTINUATION:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] CONTINUATION frame\n";
#endif

    return HandleContinuationFrame(context, frame_stream, read_offset,
                                   payload_size, frame_flags, ssl);
  case Frame::WINDOW_UPDATE:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] WINDOW_UPDATE frame\n";
#endif

    return HandleWindowUpdateFrame(context, frame_stream, read_offset,
                                   payload_size, frame_flags, ssl);
  default:
    LogError("Unknown frame type");
    return ERROR;
  }
}

int Http2FrameHandler::HandleDataFrame(void *context, uint32_t frame_stream,
                                       uint32_t read_offset,
                                       uint32_t payload_size,
                                       uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }
  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  tcp_data_map_[frame_stream] += std::string(
      reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
      payload_size);

  if (isFlagSet(frame_flags, END_STREAM_FLAG)) {
#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << tcp_data_map_[frame_stream] << std::endl;
#endif

    if (is_server_) {
      ValidatePseudoHeadersTmp(tcp_decoded_headers_map_[frame_stream]);

      // If path starts with static we use the staticcontenthandler

      auto router_ptr = router_.lock();
      if (frame_builder_ptr == nullptr) {
        return ERROR;
      }

      auto [headers, body] = router_ptr->RouteRequest(
          tcp_decoded_headers_map_[frame_stream][":method"],
          tcp_decoded_headers_map_[frame_stream][":path"],
          tcp_data_map_[frame_stream]);

      std::unordered_map<std::string, std::string> headers_map;
      headers_map.reserve(2);

      HttpCore::RespHeaderToPseudoHeader(headers, headers_map);
      headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

      std::vector<uint8_t> encoded_headers(256);
      codec_ptr->Encode(static_cast<void *>(&enc_), headers_map,
                        encoded_headers);

      if (body.empty()) {
        (void)transport_ptr->Send(
            ssl, frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream,
                                               0, 0, encoded_headers));
      } else {
        std::vector<std::vector<uint8_t>> frames;
        frames.reserve(2);
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::DATA, 0, frame_stream, 0, 0, {}, body));

        (void)transport_ptr->SendBatch(ssl, frames);
      }
    }

    (void)transport_ptr->Send(ssl, frame_builder_ptr->BuildFrame(
                                       Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);
  }
  return 0;
}

int Http2FrameHandler::HandleHeadersFrame(void *context, uint32_t frame_stream,

                                          uint32_t read_offset,
                                          uint32_t payload_size,
                                          uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }
  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  if (frame_stream == 0) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  }

  uint8_t *headerBlockStart =
      const_cast<uint8_t *>(framePtr) + FRAME_HEADER_LENGTH;
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

  uint32_t headerBlockLength = payloadEnd - headerBlockStart - padLength;

  if (headerBlockStart + headerBlockLength > payloadEnd) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::RST_STREAM, 0, frame_stream,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  // Do we really need to buffer the header blocks?
  encoded_headers_buf_map_[frame_stream].insert(
      encoded_headers_buf_map_[frame_stream].end(), headerBlockStart,
      headerBlockStart + headerBlockLength);

  if (isFlagSet(frame_flags, END_STREAM_FLAG) &&
      isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << tcp_data_map_[frame_stream] << std::endl;
#endif

    if (is_server_) {
      auto router_ptr = router_.lock();
      if (frame_builder_ptr == nullptr) {
        return ERROR;
      }

      ValidatePseudoHeadersTmp(tcp_decoded_headers_map_[frame_stream]);

      auto [headers, body] = router_ptr->RouteRequest(
          tcp_decoded_headers_map_[frame_stream][":method"],
          tcp_decoded_headers_map_[frame_stream][":path"]);

      std::unordered_map<std::string, std::string> headers_map;
      headers_map.reserve(2);

      HttpCore::RespHeaderToPseudoHeader(headers, headers_map);
      headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

      std::vector<uint8_t> encoded_headers(256);

      codec_ptr->Encode(static_cast<void *>(&enc_), headers_map,
                        encoded_headers);

      if (body == "") {
        (void)transport_ptr->Send(
            ssl, frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream,
                                               0, 0, encoded_headers));
      } else {
        std::vector<std::vector<uint8_t>> frames;
        frames.reserve(2);
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));

        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::DATA, 0, frame_stream, 0, 0, {}, body));

        (void)transport_ptr->SendBatch(ssl, frames);
      }
    }

    (void)transport_ptr->Send(ssl, frame_builder_ptr->BuildFrame(
                                       Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);

    return 0;
  }

  if (isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);
  } else {
    wait_for_cont_frame_ = true;
  }

  return 0;
}

int Http2FrameHandler::HandlePriorityFrame(void *context, uint32_t frame_stream,
                                           uint32_t read_offset,
                                           uint32_t payload_size,
                                           uint8_t frame_flags, SSL *ssl) {
  return 0;
}

int Http2FrameHandler::HandleRstStreamFrame(void *context,
                                            uint32_t frame_stream,

                                            uint32_t read_offset,
                                            uint32_t payload_size,
                                            uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  if (frame_stream == 0) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  } else if (payload_size != 4) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  uint32_t error = (framePtr[9] << 24) | (framePtr[10] << 16) |
                   (framePtr[11] << 8) | framePtr[12];

  tcp_data_map_.erase(frame_stream);
  tcp_decoded_headers_map_.erase(frame_stream);
  encoded_headers_buf_map_.erase(frame_stream);

  return 0;
}

int Http2FrameHandler::HandleSettingsFrame(void *context, uint32_t frame_stream,
                                           uint32_t read_offset,
                                           uint32_t payload_size,
                                           uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  if (payload_size % 6 != 0) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  } else if (frame_stream != 0) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  if (isFlagSet(frame_flags, HTTP2Flags::NONE_FLAG)) {
    // Parse their settings and update this connection settings
    // to be the minimum between ours and theirs

    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::SETTINGS,
                                           HTTP2Flags::SETTINGS_ACK_FLAG));

  } else if (isFlagSet(frame_flags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
    if (payload_size != 0) {
      (void)transport_ptr->Send(
          ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                             HTTP2ErrorCode::FRAME_SIZE_ERROR));
      return ERROR;
    }
  }

  return 0;
}

int Http2FrameHandler::HandlePingFrame(void *context, uint32_t frame_stream,
                                       uint32_t read_offset,
                                       uint32_t payload_size,
                                       uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  if (frame_stream != 0) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  } else if (payload_size != 8) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  if (!isFlagSet(frame_flags, HTTP2Flags::PING_ACK_FLAG)) {
    // {
    //   if (frame.size() != FRAME_HEADER_LENGTH + payload_size) {
    //     frame.resize(FRAME_HEADER_LENGTH + payload_size);
    //   }
    //
    //   memcpy(frame.data(), framePtr, FRAME_HEADER_LENGTH +
    //   payload_size); frame[4] = HTTP2Flags::PING_ACK_FLAG;
    //
    //   Send(ssl, frame);
    // }
  }

  return 0;
}

int Http2FrameHandler::HandleGoAwayFrame(void *context, uint32_t frame_stream,
                                         uint32_t read_offset,
                                         uint32_t payload_size,
                                         uint8_t frame_flags, SSL *ssl) {
  return 0;
}

int Http2FrameHandler::HandleContinuationFrame(void *context,
                                               uint32_t frame_stream,
                                               uint32_t read_offset,
                                               uint32_t payload_size,
                                               uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }
  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  if (frame_stream == 0) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  encoded_headers_buf_map_[frame_stream].insert(
      encoded_headers_buf_map_[frame_stream].end(),
      framePtr + FRAME_HEADER_LENGTH,
      framePtr + FRAME_HEADER_LENGTH + payload_size);

  if (isFlagSet(frame_flags, END_STREAM_FLAG) &&
      isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    wait_for_cont_frame_ = false;

    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
#endif

    if (is_server_) {
      auto router_ptr = router_.lock();
      if (frame_builder_ptr == nullptr) {
        return ERROR;
      }
      ValidatePseudoHeadersTmp(tcp_decoded_headers_map_[frame_stream]);

      auto [headers, body] = router_ptr->RouteRequest(
          tcp_decoded_headers_map_[frame_stream][":method"],
          tcp_decoded_headers_map_[frame_stream][":path"]);

      std::unordered_map<std::string, std::string> headers_map;
      headers_map.reserve(2);

      HttpCore::RespHeaderToPseudoHeader(headers, headers_map);
      headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

      std::vector<uint8_t> encoded_headers(256);

      codec_ptr->Encode(static_cast<void *>(&enc_), headers_map,
                        encoded_headers);

      if (body == "") {
        (void)transport_ptr->Send(
            ssl, frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream,
                                               0, 0, encoded_headers));

      } else {
        std::vector<std::vector<uint8_t>> frames;
        frames.reserve(2);
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));

        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::DATA, 0, frame_stream, 0, 0, {}, body));

        (void)transport_ptr->SendBatch(ssl, frames);
      }
    }
    (void)transport_ptr->Send(ssl, frame_builder_ptr->BuildFrame(
                                       Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);
    return 0;
  }

  if (isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    wait_for_cont_frame_ = false;
    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);

  }
  // Expecting another continuation frame ...
  else {
    wait_for_cont_frame_ = true;
  }

  return 0;
}

int Http2FrameHandler::HandleWindowUpdateFrame(void *context,
                                               uint32_t frame_stream,
                                               uint32_t read_offset,
                                               uint32_t payload_size,
                                               uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  uint32_t win_increment = (framePtr[9] << 24) | (framePtr[10] << 16) |
                           (framePtr[11] << 8) | framePtr[12];

  // std::cout << "Window increment: " << win_increment << "\n";
  if (win_increment == 0) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  } else if (payload_size != 4) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }
  // Re implement when we pass window sizes in context
  if (frame_stream == 0) {
    conn_win_size_ += win_increment;
    if (conn_win_size_ > MAX_FLOW_WINDOW_SIZE) {
      (void)transport_ptr->Send(
          ssl, frame_builder_ptr->BuildFrame(
                   Frame::GOAWAY, 0, 0, HTTP2ErrorCode::FLOW_CONTROL_ERROR));
      return ERROR;
    }
  } else {
    strm_win_size_map_[frame_stream] += win_increment;
    if (strm_win_size_map_[frame_stream] > MAX_FLOW_WINDOW_SIZE) {
      (void)transport_ptr->Send(
          ssl, frame_builder_ptr->BuildFrame(
                   Frame::GOAWAY, 0, 0, HTTP2ErrorCode::FLOW_CONTROL_ERROR));
      return ERROR;
    }
  }
  return 0;
}

int Http2FrameHandler::ProcessFrame_TS(void *context, uint8_t frame_type,
                                       uint32_t frame_stream,
                                       uint32_t read_offset,
                                       uint32_t payload_size,
                                       uint8_t frame_flags, SSL *ssl,
                                       std::mutex &mut) {
  if (wait_for_cont_frame_ && frame_type != Frame::CONTINUATION) {
    auto transport_ptr = transport_.lock();
    if (transport_ptr == nullptr) {
      return ERROR;
    }

    auto frame_builder_ptr = frame_builder_.lock();
    if (frame_builder_ptr == nullptr) {
      return ERROR;
    }

    transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  }

  switch (frame_type) {
  case Frame::DATA:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] DATA frame\n";
#endif

    return HandleDataFrame_TS(context, frame_stream, read_offset, payload_size,
                              frame_flags, ssl, mut);
  case Frame::HEADERS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] HEADERS frame\n";
#endif

    return HandleHeadersFrame_TS(context, frame_stream, read_offset,
                                 payload_size, frame_flags, ssl, mut);
  case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] PRIORITY frame\n";
#endif

    return HandlePriorityFrame_TS(context, frame_stream, read_offset,
                                  payload_size, frame_flags, ssl, mut);
  case Frame::RST_STREAM:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] RST_STREAM frame\n";
#endif

    return HandleRstStreamFrame_TS(context, frame_stream, read_offset,
                                   payload_size, frame_flags, ssl, mut);
    break;
  case Frame::SETTINGS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] SETTINGS frame\n";
#endif

    return HandleSettingsFrame_TS(context, frame_stream, read_offset,
                                  payload_size, frame_flags, ssl, mut);
  case Frame::PING:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] PING frame\n";
#endif

    return HandlePingFrame_TS(context, frame_stream, read_offset, payload_size,
                              frame_flags, ssl, mut);
  case Frame::GOAWAY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] GOAWAY frame\n";
#endif

    return HandleGoAwayFrame_TS(context, frame_stream, read_offset,
                                payload_size, frame_flags, ssl, mut);
  case Frame::CONTINUATION:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] CONTINUATION frame\n";
#endif

    return HandleContinuationFrame_TS(context, frame_stream, read_offset,
                                      payload_size, frame_flags, ssl, mut);
  case Frame::WINDOW_UPDATE:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frame_stream << "] WINDOW_UPDATE frame\n";
#endif

    return HandleWindowUpdateFrame_TS(context, frame_stream, read_offset,
                                      payload_size, frame_flags, ssl, mut);
  default:
    LogError("Unknown frame type");
    return ERROR;
  }
}

int Http2FrameHandler::HandleDataFrame_TS(void *context, uint32_t frame_stream,
                                          uint32_t read_offset,
                                          uint32_t payload_size,
                                          uint8_t frame_flags, SSL *ssl,
                                          std::mutex &mut) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }
  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  tcp_data_map_[frame_stream] += std::string(
      reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
      payload_size);

  if (isFlagSet(frame_flags, END_STREAM_FLAG)) {
#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << tcp_data_map_[frame_stream] << std::endl;
#endif

    if (is_server_) {
      auto router_ptr = router_.lock();
      if (frame_builder_ptr == nullptr) {
        return ERROR;
      }

      ValidatePseudoHeadersTmp(tcp_decoded_headers_map_[frame_stream]);

      auto [headers, body] = router_ptr->RouteRequest(
          tcp_decoded_headers_map_[frame_stream][":method"],
          tcp_decoded_headers_map_[frame_stream][":path"],
          tcp_data_map_[frame_stream]);

      std::unordered_map<std::string, std::string> headers_map;
      headers_map.reserve(2);

      HttpCore::RespHeaderToPseudoHeader(headers, headers_map);
      headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

      std::vector<uint8_t> encoded_headers(256);
      codec_ptr->Encode(static_cast<void *>(&enc_), headers_map,
                        encoded_headers);

      if (body.empty()) {
        (void)transport_ptr->Send_TS(
            ssl,
            frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream, 0, 0,
                                          encoded_headers),
            mut);
      } else {
        std::vector<std::vector<uint8_t>> frames;
        frames.reserve(2);
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::DATA, 0, frame_stream, 0, 0, {}, body));

        (void)transport_ptr->SendBatch_TS(ssl, frames, mut);
      }
    }
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536),
        mut);

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);
  }
  return 0;
}

int Http2FrameHandler::HandleHeadersFrame_TS(void *context,
                                             uint32_t frame_stream,

                                             uint32_t read_offset,
                                             uint32_t payload_size,
                                             uint8_t frame_flags, SSL *ssl,
                                             std::mutex &mut) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }
  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  if (frame_stream == 0) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  }

  uint8_t *headerBlockStart =
      const_cast<uint8_t *>(framePtr) + FRAME_HEADER_LENGTH;
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

  uint32_t headerBlockLength = payloadEnd - headerBlockStart - padLength;

  if (headerBlockStart + headerBlockLength > payloadEnd) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::RST_STREAM, 0, frame_stream,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  }

  // Do we really need to buffer the header blocks?
  encoded_headers_buf_map_[frame_stream].insert(
      encoded_headers_buf_map_[frame_stream].end(), headerBlockStart,
      headerBlockStart + headerBlockLength);

  if (isFlagSet(frame_flags, END_STREAM_FLAG) &&
      isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << tcp_data_map_[frame_stream] << std::endl;
#endif
    if (is_server_) {
      auto router_ptr = router_.lock();
      if (frame_builder_ptr == nullptr) {
        return ERROR;
      }
      ValidatePseudoHeadersTmp(tcp_decoded_headers_map_[frame_stream]);

      auto [headers, body] = router_ptr->RouteRequest(
          tcp_decoded_headers_map_[frame_stream][":method"],
          tcp_decoded_headers_map_[frame_stream][":path"]);

      std::unordered_map<std::string, std::string> headers_map;
      headers_map.reserve(2);

      HttpCore::RespHeaderToPseudoHeader(headers, headers_map);
      headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

      std::vector<uint8_t> encoded_headers(256);

      codec_ptr->Encode(static_cast<void *>(&enc_), headers_map,
                        encoded_headers);

      if (body == "") {
        (void)transport_ptr->Send_TS(
            ssl,
            frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream, 0, 0,
                                          encoded_headers),
            mut);
      } else {
        std::vector<std::vector<uint8_t>> frames;
        frames.reserve(2);
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));

        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::DATA, 0, frame_stream, 0, 0, {}, body));

        (void)transport_ptr->SendBatch_TS(ssl, frames, mut);
      }
    }
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536),
        mut);

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);

    return 0;
  }

  if (isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);
  } else {
    wait_for_cont_frame_ = true;
  }

  return 0;
}

int Http2FrameHandler::HandlePriorityFrame_TS(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl, std::mutex &mut) {
  return 0;
}

int Http2FrameHandler::HandleRstStreamFrame_TS(void *context,
                                               uint32_t frame_stream,

                                               uint32_t read_offset,
                                               uint32_t payload_size,
                                               uint8_t frame_flags, SSL *ssl,
                                               std::mutex &mut) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  if (frame_stream == 0) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  } else if (payload_size != 4) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  }

  uint32_t error = (framePtr[9] << 24) | (framePtr[10] << 16) |
                   (framePtr[11] << 8) | framePtr[12];

  tcp_data_map_.erase(frame_stream);
  tcp_decoded_headers_map_.erase(frame_stream);
  encoded_headers_buf_map_.erase(frame_stream);

  return 0;
}

int Http2FrameHandler::HandleSettingsFrame_TS(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl, std::mutex &mut) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  if (payload_size % 6 != 0) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  } else if (frame_stream != 0) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  }

  if (isFlagSet(frame_flags, HTTP2Flags::NONE_FLAG)) {
    // Parse their settings and update this connection settings
    // to be the minimum between ours and theirs

    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::SETTINGS,
                                      HTTP2Flags::SETTINGS_ACK_FLAG),
        mut);

  } else if (isFlagSet(frame_flags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
    if (payload_size != 0) {
      (void)transport_ptr->Send_TS(
          ssl,
          frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FRAME_SIZE_ERROR),
          mut);
      return ERROR;
    }
  }

  return 0;
}

int Http2FrameHandler::HandlePingFrame_TS(void *context, uint32_t frame_stream,
                                          uint32_t read_offset,
                                          uint32_t payload_size,
                                          uint8_t frame_flags, SSL *ssl,
                                          std::mutex &mut) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  if (frame_stream != 0) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  } else if (payload_size != 8) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  }

  if (!isFlagSet(frame_flags, HTTP2Flags::PING_ACK_FLAG)) {
    // {
    //   if (frame.size() != FRAME_HEADER_LENGTH + payload_size) {
    //     frame.resize(FRAME_HEADER_LENGTH + payload_size);
    //   }
    //
    //   memcpy(frame.data(), framePtr, FRAME_HEADER_LENGTH +
    //   payload_size); frame[4] = HTTP2Flags::PING_ACK_FLAG;
    //
    //   Send(ssl, frame);
    // }
  }

  return 0;
}

int Http2FrameHandler::HandleGoAwayFrame_TS(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl, std::mutex &mut) {
  return 0;
}

int Http2FrameHandler::HandleContinuationFrame_TS(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl, std::mutex &mut) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }
  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  if (frame_stream == 0) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  encoded_headers_buf_map_[frame_stream].insert(
      encoded_headers_buf_map_[frame_stream].end(),
      framePtr + FRAME_HEADER_LENGTH,
      framePtr + FRAME_HEADER_LENGTH + payload_size);

  if (isFlagSet(frame_flags, END_STREAM_FLAG) &&
      isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    wait_for_cont_frame_ = false;

    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
#endif

    if (is_server_) {
      auto router_ptr = router_.lock();
      if (frame_builder_ptr == nullptr) {
        return ERROR;
      }

      ValidatePseudoHeadersTmp(tcp_decoded_headers_map_[frame_stream]);

      auto [headers, body] = router_ptr->RouteRequest(
          tcp_decoded_headers_map_[frame_stream][":method"],
          tcp_decoded_headers_map_[frame_stream][":path"]);

      std::unordered_map<std::string, std::string> headers_map;
      headers_map.reserve(2);

      HttpCore::RespHeaderToPseudoHeader(headers, headers_map);
      headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

      std::vector<uint8_t> encoded_headers(256);

      codec_ptr->Encode(static_cast<void *>(&enc_), headers_map,
                        encoded_headers);

      if (body == "") {
        (void)transport_ptr->Send_TS(
            ssl,
            frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream, 0, 0,
                                          encoded_headers),
            mut);

      } else {
        std::vector<std::vector<uint8_t>> frames;
        frames.reserve(2);
        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));

        frames.emplace_back(frame_builder_ptr->BuildFrame(
            Frame::DATA, 0, frame_stream, 0, 0, {}, body));

        (void)transport_ptr->SendBatch_TS(ssl, frames, mut);
      }
    }

    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536),
        mut);

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);
    return 0;
  }

  if (isFlagSet(frame_flags, END_HEADERS_FLAG)) {
    wait_for_cont_frame_ = false;
    codec_ptr->Decode(static_cast<void *>(&dec_),
                      encoded_headers_buf_map_[frame_stream],
                      tcp_decoded_headers_map_[frame_stream]);

  }
  // Expecting another continuation frame ...
  else {
    wait_for_cont_frame_ = true;
  }

  return 0;
}

int Http2FrameHandler::HandleWindowUpdateFrame_TS(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl, std::mutex &mut) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  const uint8_t *framePtr = read_buf.data() + read_offset;

  uint32_t win_increment = (framePtr[9] << 24) | (framePtr[10] << 16) |
                           (framePtr[11] << 8) | framePtr[12];

  // std::cout << "Window increment: " << win_increment << "\n";
  if (win_increment == 0) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  } else if (payload_size != 4) {
    (void)transport_ptr->Send_TS(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  }
  // Re implement when we pass window sizes in context
  if (frame_stream == 0) {
    conn_win_size_ += win_increment;
    if (conn_win_size_ > MAX_FLOW_WINDOW_SIZE) {
      (void)transport_ptr->Send_TS(
          ssl,
          frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FLOW_CONTROL_ERROR),
          mut);
      return ERROR;
    }
  } else {
    strm_win_size_map_[frame_stream] += win_increment;
    if (strm_win_size_map_[frame_stream] > MAX_FLOW_WINDOW_SIZE) {
      (void)transport_ptr->Send_TS(
          ssl,
          frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FLOW_CONTROL_ERROR),
          mut);
      return ERROR;
    }
  }
  return 0;
}
