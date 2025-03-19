// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/http2_request_handler.h"

#include <fcntl.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../include/database_handler.h"
#include "../include/header_parser.h"
#include "../include/http2_frame_builder.h"
#include "../include/log.h"
#include "../include/utils.h"

// #define HTTP2_DEBUG

bool Http2RequestHandler::static_init_ = false;
HeaderParser Http2RequestHandler::header_parser_;
std::weak_ptr<TcpTransport> Http2RequestHandler::transport_;
std::weak_ptr<Http2FrameBuilder> Http2RequestHandler::frame_builder_;
std::weak_ptr<HpackCodec> Http2RequestHandler::codec_;
std::weak_ptr<Router> Http2RequestHandler::router_;
std::weak_ptr<StaticContentHandler>
    Http2RequestHandler::static_content_handler_;
std::weak_ptr<DatabaseHandler> Http2RequestHandler::database_handler_;

Http2RequestHandler::Http2RequestHandler(
    const std::vector<uint8_t> &read_buf,
    const std::shared_ptr<TcpTransport> &transport,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder,
    const std::shared_ptr<HpackCodec> &hpack_codec,
    const std::shared_ptr<Router> &router,
    const std::shared_ptr<StaticContentHandler> &content_handler,
    const std::shared_ptr<DatabaseHandler> &db_handler)
    : read_buf(read_buf),
      enc_(),
      dec_(),
      conn_win_size_(0),
      wait_for_cont_frame_(false) {
  if (!static_init_) {
    InitializeSharedResources(transport, frame_builder, hpack_codec, router,
                              content_handler, db_handler);
  }

  if (router != nullptr && content_handler != nullptr) {
    is_server_ = true;
  } else {
    is_server_ = false;
  }

  lshpack_enc_init(&enc_);
  lshpack_dec_init(&dec_);
}

void Http2RequestHandler::InitializeSharedResources(
    const std::shared_ptr<TcpTransport> &transport,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder,
    const std::shared_ptr<HpackCodec> &hpack_codec,
    const std::shared_ptr<Router> &router,
    const std::shared_ptr<StaticContentHandler> &content_handler,
    const std::shared_ptr<DatabaseHandler> &db_handler) {
  transport_ = transport;
  frame_builder_ = frame_builder;
  codec_ = hpack_codec;
  router_ = router;
  static_content_handler_ = content_handler;
  database_handler_ = db_handler;
  static_init_ = true;
}

Http2RequestHandler::~Http2RequestHandler() {
  lshpack_enc_cleanup(&enc_);
  lshpack_dec_cleanup(&dec_);
}

int Http2RequestHandler::ProcessFrame(void *context, uint8_t frame_type,
                                      uint32_t frame_stream,
                                      uint32_t read_offset,
                                      uint32_t payload_size,
                                      uint8_t frame_flags, SSL *ssl) {
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

      return HandleHeadersFrame(context, frame_stream, read_offset,
                                payload_size, frame_flags, ssl);
    case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] PRIORITY frame\n";
#endif

      return HandlePriorityFrame(context, frame_stream, read_offset,
                                 payload_size, frame_flags, ssl);
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

      return HandleSettingsFrame(context, frame_stream, read_offset,
                                 payload_size, frame_flags, ssl);
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

std::vector<uint8_t> Http2RequestHandler::EncodeHeaders(
    const std::unordered_map<std::string, std::string> &headers_map) {
  std::vector<uint8_t> encoded_headers(256);

  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return {};
  }

  codec_ptr->Encode(static_cast<void *>(&enc_), headers_map, encoded_headers);
  return encoded_headers;
}

int Http2RequestHandler::HandleStaticContent(
    uint32_t frame_stream, SSL *ssl,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
    std::string &path) {
  auto content_handler_ptr = static_content_handler_.lock();
  if (content_handler_ptr == nullptr) {
    return ERROR;
  }

  const auto &req_headers_map = tcp_decoded_headers_map_[frame_stream];
  uint64_t file_size = content_handler_ptr->HandleFile(
      path, req_headers_map.contains("accept-encoding")
                ? req_headers_map.at("accept-encoding")
                : "");

  if (file_size == 0) {
    std::cout << "File does not exist?\n";
    // File not found, use router as fallback
    return HandleRouterRequest(frame_stream, ssl, frame_builder_ptr,
                               transport_ptr, method, path,
                               tcp_data_map_[frame_stream]);
  }

  std::string headers =
      content_handler_ptr->BuildHeadersForFileTransfer(path, file_size);

  std::unordered_map<std::string, std::string> headers_map =
      header_parser_.ConvertResponseToPseudoHeaders(std::string_view(headers));

  headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

  auto encoded_headers = EncodeHeaders(headers_map);
  if (encoded_headers.empty()) {
    return ERROR;
  }

  (void)transport_ptr->Send(
      ssl, frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream, 0, 0,
                                         encoded_headers));

  int fd = open(path.c_str(), O_RDONLY);
  if (fd == -1) {
    LogError("Opening file: " + path);
    return ERROR;
  }

  (void)transport_ptr->SendBatch(
      ssl,
      frame_builder_ptr->BuildDataFramesFromFile(fd, file_size, frame_stream));

  close(fd);
  return 0;
}

int Http2RequestHandler::HandleDatabaseRequest(
    uint32_t frame_stream, SSL *ssl,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
    std::string &path, const std::string &data) {
  auto router_ptr = router_.lock();
  if (router_ptr == nullptr) {
    return ERROR;
  }

  std::string body;

  std::unordered_map<std::string, std::string> headers_map;

  auto opt = router_ptr->OptRouteRequest(method, path, data);
  if (opt) {
    auto &[pseudo_headers, body_ref] = *opt;
    headers_map = pseudo_headers;
    body = body_ref;
    headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  } else {
    auto [headers, body_ref] = router_ptr->RouteRequest(method, path, data);
    body = body_ref;
    headers_map = header_parser_.ConvertResponseToPseudoHeaders(
        std::string_view(headers));

    headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  }

  auto encoded_headers = EncodeHeaders(headers_map);
  if (encoded_headers.empty()) {
    return ERROR;
  }

  // Send response
  if (body.empty()) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(
                 Frame::HEADERS, HTTP2Flags::END_STREAM_FLAG, frame_stream, 0,
                 0, encoded_headers));
  } else {
    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);
    frames.emplace_back(frame_builder_ptr->BuildFrame(
        Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));
    frames.emplace_back(frame_builder_ptr->BuildFrame(
        Frame::DATA, 0, frame_stream, 0, 0, {}, body));

    (void)transport_ptr->SendBatch(ssl, frames);
  }

  return 0;
}

int Http2RequestHandler::HandleRouterRequest(
    uint32_t frame_stream, SSL *ssl,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
    std::string &path, const std::string &data) {
  auto router_ptr = router_.lock();
  if (router_ptr == nullptr) {
    return ERROR;
  }

  std::string body;

  std::unordered_map<std::string, std::string> headers_map;

  auto opt = router_ptr->OptRouteRequest(method, path, data);
  if (opt) {
    auto &[pseudo_headers, body_ref] = *opt;
    headers_map = pseudo_headers;
    body = body_ref;
    headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  } else {
    auto [headers, body_ref] = router_ptr->RouteRequest(method, path, data);
    body = body_ref;
    headers_map = header_parser_.ConvertResponseToPseudoHeaders(
        std::string_view(headers));

    headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  }

  auto encoded_headers = EncodeHeaders(headers_map);
  if (encoded_headers.empty()) {
    return ERROR;
  }

  // Send response
  if (body.empty()) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(
                 Frame::HEADERS, HTTP2Flags::END_STREAM_FLAG, frame_stream, 0,
                 0, encoded_headers));
  } else {
    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);
    frames.emplace_back(frame_builder_ptr->BuildFrame(
        Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));
    frames.emplace_back(frame_builder_ptr->BuildFrame(
        Frame::DATA, 0, frame_stream, 0, 0, {}, body));

    (void)transport_ptr->SendBatch(ssl, frames);
  }

  return 0;
}

int Http2RequestHandler::AnswerRequest(
    uint32_t frame_stream, SSL *ssl,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<TcpTransport> &transport_ptr) {
  static constexpr std::string_view db_path = "/db/";
  static constexpr uint8_t db_path_size = db_path.size();

  static constexpr std::string_view static_path = "/static/";
  static constexpr uint8_t static_path_size = static_path.size();

  header_parser_.ValidateRequestPseudoHeaders(
      tcp_decoded_headers_map_[frame_stream]);

  std::string &path = tcp_decoded_headers_map_[frame_stream][":path"];
  std::string &method = tcp_decoded_headers_map_[frame_stream][":method"];
  std::string &data = tcp_data_map_[frame_stream];

  // Handle static content
  if (path.size() > static_path_size && path.starts_with(static_path)) {
    return HandleStaticContent(frame_stream, ssl, frame_builder_ptr,
                               transport_ptr, method, path);

  } else if (path.size() > db_path_size && path.starts_with(db_path)) {
    std::cout << "Sending query\n";
    auto database_ptr = database_handler_.lock();

    std::string db_table =
        path.substr(db_path.size(), path.size() - db_path.size());

    auto [headers_map, body] = database_ptr->OptHandleQuery(
        tcp_decoded_headers_map_[frame_stream][":method"], db_table,
        tcp_data_map_[frame_stream]);

    headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

    auto encoded_headers = EncodeHeaders(headers_map);
    if (encoded_headers.empty()) {
      return ERROR;
    }

    // Send response
    if (body.empty()) {
      (void)transport_ptr->Send(
          ssl, frame_builder_ptr->BuildFrame(
                   Frame::HEADERS, HTTP2Flags::END_STREAM_FLAG, frame_stream, 0,
                   0, encoded_headers));
    } else {
      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);
      frames.emplace_back(frame_builder_ptr->BuildFrame(
          Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));
      frames.emplace_back(frame_builder_ptr->BuildFrame(
          Frame::DATA, 0, frame_stream, 0, 0, {}, body));

      (void)transport_ptr->SendBatch(ssl, frames);
    }

    return 0;
  }

  // Handle dynamic content via router
  return HandleRouterRequest(frame_stream, ssl, frame_builder_ptr,
                             transport_ptr, method, path, data);
}

int Http2RequestHandler::HandleDataFrame(void *context, uint32_t frame_stream,
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

  uint32_t end_read_offset = (read_offset + payload_size) % read_buf.size();

  if (end_read_offset < read_offset) {
    tcp_data_map_[frame_stream] =
        std::string(&read_buf[read_offset], &read_buf[read_buf.size()]);
    tcp_data_map_[frame_stream] +=
        std::string(&read_buf[0], &read_buf[end_read_offset]);
  } else {
    tcp_data_map_[frame_stream] =
        std::string(&read_buf[read_offset], &read_buf[end_read_offset]);
  }

  if (isFlagSet(frame_flags, END_STREAM_FLAG)) {
#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << tcp_data_map_[frame_stream] << std::endl;
#endif

    if (is_server_) {
      AnswerRequest(frame_stream, ssl, frame_builder_ptr, transport_ptr);
    }

    (void)transport_ptr->Send(ssl, frame_builder_ptr->BuildFrame(
                                       Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);
  }
  return 0;
}

int Http2RequestHandler::HandleHeadersFrame(void *context,
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

  uint32_t header_block_start = read_offset;
  uint32_t header_block_end = (read_offset + payload_size) % read_buf.size();

  uint8_t pad_len = 0;

  if (isFlagSet(frame_flags, HTTP2Flags::PADDED_FLAG)) {
    pad_len = read_buf[read_offset];
    header_block_start = (header_block_start + 1) % read_buf.size();
    // In case there is padding we need to adjust the header block end idx
    header_block_end = (read_offset + payload_size - pad_len) % read_buf.size();
  }

  if (isFlagSet(frame_flags, HTTP2Flags::PRIORITY_FLAG)) {
    header_block_start = (header_block_start + 5) % read_buf.size();
  }

  // 2 parts to read
  if (header_block_end < header_block_start) {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(),
        &read_buf[header_block_start], &read_buf[read_buf.size()]);

    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[0],
        &read_buf[header_block_end]);
  } else {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(),
        &read_buf[header_block_start], &read_buf[header_block_end]);
  }

  // Do we really need to buffer the header blocks?
  // encoded_headers_buf_map_[frame_stream].insert(
  //     encoded_headers_buf_map_[frame_stream].end(), header_block_start,
  //     header_block_start + headerBlockLength);

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
      AnswerRequest(frame_stream, ssl, frame_builder_ptr, transport_ptr);
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

int Http2RequestHandler::HandlePriorityFrame(void *context,
                                             uint32_t frame_stream,
                                             uint32_t read_offset,
                                             uint32_t payload_size,
                                             uint8_t frame_flags, SSL *ssl) {
  return 0;
}

int Http2RequestHandler::HandleRstStreamFrame(void *context,
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

  tcp_data_map_.erase(frame_stream);
  tcp_decoded_headers_map_.erase(frame_stream);
  encoded_headers_buf_map_.erase(frame_stream);

  return 0;
}

int Http2RequestHandler::HandleSettingsFrame(void *context,
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

int Http2RequestHandler::HandlePingFrame(void *context, uint32_t frame_stream,
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

int Http2RequestHandler::HandleGoAwayFrame(void *context, uint32_t frame_stream,
                                           uint32_t read_offset,
                                           uint32_t payload_size,
                                           uint8_t frame_flags, SSL *ssl) {
  return 0;
}

int Http2RequestHandler::HandleContinuationFrame(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl) {
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

  uint32_t end_read_offset = (read_offset + payload_size) % read_buf.size();

  if (end_read_offset < read_offset) {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[read_offset],
        &read_buf[read_buf.size()]);
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[0],
        &read_buf[end_read_offset]);
  } else {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[read_offset],
        &read_buf[end_read_offset]);
  }

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
      AnswerRequest(frame_stream, ssl, frame_builder_ptr, transport_ptr);
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
  } else {
    wait_for_cont_frame_ = true;
  }

  return 0;
}

int Http2RequestHandler::HandleWindowUpdateFrame(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl) {
  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  uint32_t win_increment =
      (read_buf[(read_offset + 0) % read_buf.size()] << 24) |
      (read_buf[(read_offset + 1) % read_buf.size()] << 16) |
      (read_buf[(read_offset + 2) % read_buf.size()] << 8) |
      read_buf[(read_offset + 3) % read_buf.size()];

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

int Http2RequestHandler::ProcessFrame_TS(void *context, uint8_t frame_type,
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

      return HandleDataFrame(context, frame_stream, read_offset, payload_size,
                             frame_flags, ssl, mut);
    case Frame::HEADERS:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] HEADERS frame\n";
#endif

      return HandleHeadersFrame(context, frame_stream, read_offset,
                                payload_size, frame_flags, ssl, mut);
    case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] PRIORITY frame\n";
#endif

      return HandlePriorityFrame(context, frame_stream, read_offset,
                                 payload_size, frame_flags, ssl, mut);
    case Frame::RST_STREAM:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] RST_STREAM frame\n";
#endif

      return HandleRstStreamFrame(context, frame_stream, read_offset,
                                  payload_size, frame_flags, ssl, mut);
      break;
    case Frame::SETTINGS:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] SETTINGS frame\n";
#endif

      return HandleSettingsFrame(context, frame_stream, read_offset,
                                 payload_size, frame_flags, ssl, mut);
    case Frame::PING:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] PING frame\n";
#endif

      return HandlePingFrame(context, frame_stream, read_offset, payload_size,
                             frame_flags, ssl, mut);
    case Frame::GOAWAY:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] GOAWAY frame\n";
#endif

      return HandleGoAwayFrame(context, frame_stream, read_offset, payload_size,
                               frame_flags, ssl, mut);
    case Frame::CONTINUATION:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] CONTINUATION frame\n";
#endif

      return HandleContinuationFrame(context, frame_stream, read_offset,
                                     payload_size, frame_flags, ssl, mut);
    case Frame::WINDOW_UPDATE:
#ifdef HTTP2_DEBUG
      std::cout << "[strm][" << frame_stream << "] WINDOW_UPDATE frame\n";
#endif

      return HandleWindowUpdateFrame(context, frame_stream, read_offset,
                                     payload_size, frame_flags, ssl, mut);
    default:
      LogError("Unknown frame type");
      return ERROR;
  }
}

int Http2RequestHandler::HandleStaticContent(
    uint32_t frame_stream, SSL *ssl,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
    std::string &path, std::mutex &mut) {
  auto content_handler_ptr = static_content_handler_.lock();
  if (content_handler_ptr == nullptr) {
    return ERROR;
  }

  const auto &req_headers_map = tcp_decoded_headers_map_[frame_stream];
  uint64_t file_size = content_handler_ptr->HandleFile(
      path, req_headers_map.contains("accept-encoding")
                ? req_headers_map.at("accept-encoding")
                : "");

  if (file_size == 0) {
    std::cout << "File does not exist?\n";
    // File not found, use router as fallback
    return HandleRouterRequest(frame_stream, ssl, frame_builder_ptr,
                               transport_ptr, method, path,
                               tcp_data_map_[frame_stream]);
  }

  std::string headers =
      content_handler_ptr->BuildHeadersForFileTransfer(path, file_size);

  std::unordered_map<std::string, std::string> headers_map =
      header_parser_.ConvertResponseToPseudoHeaders(std::string_view(headers));

  headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";

  auto encoded_headers = EncodeHeaders(headers_map);
  if (encoded_headers.empty()) {
    return ERROR;
  }

  (void)transport_ptr->Send(
      ssl,
      frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream, 0, 0,
                                    encoded_headers),
      mut);

  int fd = open(path.c_str(), O_RDONLY);
  if (fd == -1) {
    LogError("Opening file: " + path);
    return ERROR;
  }

  (void)transport_ptr->SendBatch(
      ssl,
      frame_builder_ptr->BuildDataFramesFromFile(fd, file_size, frame_stream),
      mut);

  close(fd);
  return 0;
}

int Http2RequestHandler::HandleRouterRequest(
    uint32_t frame_stream, SSL *ssl,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
    std::string &path, const std::string &data, std::mutex &mut) {
  auto router_ptr = router_.lock();
  if (router_ptr == nullptr) {
    return ERROR;
  }

  std::string body;

  std::unordered_map<std::string, std::string> headers_map;

  auto opt = router_ptr->OptRouteRequest(method, path, data);
  if (opt) {
    auto &[pseudo_headers, body_ref] = *opt;
    headers_map = pseudo_headers;
    body = body_ref;
    headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  } else {
    auto [headers, body_ref] = router_ptr->RouteRequest(method, path, data);
    body = body_ref;
    headers_map = header_parser_.ConvertResponseToPseudoHeaders(
        std::string_view(headers));

    headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  }

  auto encoded_headers = EncodeHeaders(headers_map);
  if (encoded_headers.empty()) {
    return ERROR;
  }

  // Send response
  if (body.empty()) {
    (void)transport_ptr->Send(
        ssl, frame_builder_ptr->BuildFrame(
                 Frame::HEADERS, HTTP2Flags::END_STREAM_FLAG, frame_stream, 0,
                 0, encoded_headers));
  } else {
    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);
    frames.emplace_back(frame_builder_ptr->BuildFrame(
        Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));
    frames.emplace_back(frame_builder_ptr->BuildFrame(
        Frame::DATA, 0, frame_stream, 0, 0, {}, body));

    (void)transport_ptr->SendBatch(ssl, frames, mut);
  }

  return 0;
}

int Http2RequestHandler::AnswerRequest(
    uint32_t frame_stream, SSL *ssl,
    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<TcpTransport> &transport_ptr, std::mutex &mut) {
  static constexpr std::string_view static_path = "/static/";
  static constexpr uint8_t static_path_size = static_path.size();

  header_parser_.ValidateRequestPseudoHeaders(
      tcp_decoded_headers_map_[frame_stream]);

  std::string &path = tcp_decoded_headers_map_[frame_stream][":path"];
  std::string &method = tcp_decoded_headers_map_[frame_stream][":method"];
  std::string &data = tcp_data_map_[frame_stream];

  std::cout << "Sending query\n";
  auto database_ptr = database_handler_.lock()->HandleQuery(
      tcp_decoded_headers_map_[frame_stream][":method"],
      tcp_decoded_headers_map_[frame_stream][":path"],
      tcp_data_map_[frame_stream]);

  // Handle static content
  if (path.size() > static_path_size && path.starts_with(static_path)) {
    return HandleStaticContent(frame_stream, ssl, frame_builder_ptr,
                               transport_ptr, method, path, mut);
  }

  // Handle dynamic content via router
  return HandleRouterRequest(frame_stream, ssl, frame_builder_ptr,
                             transport_ptr, method, path, data, mut);
}

int Http2RequestHandler::HandleDataFrame(void *context, uint32_t frame_stream,
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

  uint32_t end_read_offset = (read_offset + payload_size) % read_buf.size();

  if (end_read_offset < read_offset) {
    tcp_data_map_[frame_stream] =
        std::string(&read_buf[read_offset], &read_buf[read_buf.size()]);
    tcp_data_map_[frame_stream] +=
        std::string(&read_buf[0], &read_buf[end_read_offset]);
  } else {
    tcp_data_map_[frame_stream] =
        std::string(&read_buf[read_offset], &read_buf[end_read_offset]);
  }

  if (isFlagSet(frame_flags, END_STREAM_FLAG)) {
#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : tcp_decoded_headers_map_[frame_stream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << tcp_data_map_[frame_stream] << std::endl;
#endif

    if (is_server_) {
      AnswerRequest(frame_stream, ssl, frame_builder_ptr, transport_ptr, mut);
    }
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536),
        mut);

    tcp_data_map_.erase(frame_stream);
    tcp_decoded_headers_map_.erase(frame_stream);
    encoded_headers_buf_map_.erase(frame_stream);
  }
  return 0;
}

int Http2RequestHandler::HandleHeadersFrame(void *context,
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

  if (frame_stream == 0) {
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  }

  uint32_t header_block_start = read_offset;
  uint32_t header_block_end = (read_offset + payload_size) % read_buf.size();

  uint8_t pad_len = 0;

  if (isFlagSet(frame_flags, HTTP2Flags::PADDED_FLAG)) {
    pad_len = read_buf[read_offset];
    header_block_start = (header_block_start + 1) % read_buf.size();
    // In case there is padding we need to adjust the header block end idx
    header_block_end = (read_offset + payload_size - pad_len) % read_buf.size();
  }

  if (isFlagSet(frame_flags, HTTP2Flags::PRIORITY_FLAG)) {
    header_block_start = (header_block_start + 5) % read_buf.size();
  }

  // 2 parts to read
  if (header_block_end < header_block_start) {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(),
        &read_buf[header_block_start], &read_buf[read_buf.size()]);

    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[0],
        &read_buf[header_block_end]);
  } else {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(),
        &read_buf[header_block_start], &read_buf[header_block_end]);
  }

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
      AnswerRequest(frame_stream, ssl, frame_builder_ptr, transport_ptr, mut);
    }
    (void)transport_ptr->Send(
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

int Http2RequestHandler::HandlePriorityFrame(
    void *context, uint32_t frame_stream, uint32_t read_offset,
    uint32_t payload_size, uint8_t frame_flags, SSL *ssl, std::mutex &mut) {
  return 0;
}

int Http2RequestHandler::HandleRstStreamFrame(void *context,
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

  if (frame_stream == 0) {
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  } else if (payload_size != 4) {
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  }

  tcp_data_map_.erase(frame_stream);
  tcp_decoded_headers_map_.erase(frame_stream);
  encoded_headers_buf_map_.erase(frame_stream);

  return 0;
}

int Http2RequestHandler::HandleSettingsFrame(
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
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  } else if (frame_stream != 0) {
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  }

  if (isFlagSet(frame_flags, HTTP2Flags::NONE_FLAG)) {
    // Parse their settings and update this connection settings
    // to be the minimum between ours and theirs

    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::SETTINGS,
                                      HTTP2Flags::SETTINGS_ACK_FLAG),
        mut);

  } else if (isFlagSet(frame_flags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
    if (payload_size != 0) {
      (void)transport_ptr->Send(
          ssl,
          frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FRAME_SIZE_ERROR),
          mut);
      return ERROR;
    }
  }

  return 0;
}

int Http2RequestHandler::HandlePingFrame(void *context, uint32_t frame_stream,
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
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  } else if (payload_size != 8) {
    (void)transport_ptr->Send(
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

int Http2RequestHandler::HandleGoAwayFrame(void *context, uint32_t frame_stream,
                                           uint32_t read_offset,
                                           uint32_t payload_size,
                                           uint8_t frame_flags, SSL *ssl,
                                           std::mutex &mut) {
  return 0;
}

int Http2RequestHandler::HandleContinuationFrame(
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
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::PROTOCOL_ERROR),
        mut);
    return ERROR;
  }

  uint32_t end_read_offset = (read_offset + payload_size) % read_buf.size();

  if (end_read_offset < read_offset) {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[read_offset],
        &read_buf[read_buf.size()]);
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[0],
        &read_buf[end_read_offset]);
  } else {
    encoded_headers_buf_map_[frame_stream].insert(
        encoded_headers_buf_map_[frame_stream].end(), &read_buf[read_offset],
        &read_buf[end_read_offset]);
  }

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
      AnswerRequest(frame_stream, ssl, frame_builder_ptr, transport_ptr, mut);
    }

    (void)transport_ptr->Send(
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

  } else {
    wait_for_cont_frame_ = true;
  }

  return 0;
}

int Http2RequestHandler::HandleWindowUpdateFrame(
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

  uint32_t win_increment =
      (read_buf[(read_offset + 0) % read_buf.size()] << 24) |
      (read_buf[(read_offset + 1) % read_buf.size()] << 16) |
      (read_buf[(read_offset + 2) % read_buf.size()] << 8) |
      read_buf[(read_offset + 3) % read_buf.size()];

  // std::cout << "Window increment: " << win_increment << "\n";
  if (win_increment == 0) {
    (void)transport_ptr->Send(
        ssl,
        frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                      HTTP2ErrorCode::FRAME_SIZE_ERROR),
        mut);
    return ERROR;
  } else if (payload_size != 4) {
    (void)transport_ptr->Send(
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
      (void)transport_ptr->Send(
          ssl,
          frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FLOW_CONTROL_ERROR),
          mut);
      return ERROR;
    }
  } else {
    strm_win_size_map_[frame_stream] += win_increment;
    if (strm_win_size_map_[frame_stream] > MAX_FLOW_WINDOW_SIZE) {
      (void)transport_ptr->Send(
          ssl,
          frame_builder_ptr->BuildFrame(Frame::GOAWAY, 0, 0,
                                        HTTP2ErrorCode::FLOW_CONTROL_ERROR),
          mut);
      return ERROR;
    }
  }
  return 0;
}
