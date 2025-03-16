// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/http3_frame_handler.h"

#include <fcntl.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/log.h"

// #define HTTP3_DEBUG
// #define ECHO
static uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                           const std::vector<uint8_t>::iterator &end) {
  // Check if there's enough data for at least the first byte
  if (iter + 1 >= end) {
    LogError("Buffer overflow in ReadVarint");
    return ERROR;
  }

  // Read the first byte
  uint64_t value = *iter++;
  uint8_t prefix = value >> 6;
  size_t length = 1 << prefix;

  value &= 0x3F;

  // Check if we have enough data for the full varint
  if (iter + length - 1 >= end) {
    LogError("Error: Not enough data in buffer for full varint\n");
    return ERROR;
  }

  // Read the remaining bytes of the varint
  for (size_t i = 1; i < length; ++i) {
    value = (value << 8) | *iter++;
  }

  return value;
}

bool Http3FrameHandler::static_init_;
HeaderParser Http3FrameHandler::header_parser_;
std::weak_ptr<QuicTransport> Http3FrameHandler::transport_;
std::weak_ptr<Http3FrameBuilder> Http3FrameHandler::frame_builder_;
std::weak_ptr<QpackCodec> Http3FrameHandler::codec_;
std::weak_ptr<Router> Http3FrameHandler::router_;
std::weak_ptr<StaticContentHandler> Http3FrameHandler::static_content_handler_;

Http3FrameHandler::Http3FrameHandler(
    const std::shared_ptr<QuicTransport> &transport,
    const std::shared_ptr<Http3FrameBuilder> &frame_builder,
    const std::shared_ptr<QpackCodec> &codec,
    const std::shared_ptr<Router> &router,
    const std::shared_ptr<StaticContentHandler> &content_handler) {
  if (!static_init_) {
    InitializeSharedResources(transport, frame_builder, codec, router,
                              content_handler);
  }

  if (router != nullptr && content_handler != nullptr) {
    is_server_ = true;
  } else {
    is_server_ = false;
  }

  // lsqpack_enc_init(&enc_);
  // lsqpack_dec_init(&dec_);
}

void Http3FrameHandler::InitializeSharedResources(
    const std::shared_ptr<QuicTransport> &transport,
    const std::shared_ptr<Http3FrameBuilder> &frame_builder,
    const std::shared_ptr<QpackCodec> &hpack_codec,
    const std::shared_ptr<Router> &router,
    const std::shared_ptr<StaticContentHandler> &content_handler) {
  transport_ = transport;
  frame_builder_ = frame_builder;
  codec_ = hpack_codec;
  router_ = router;
  static_content_handler_ = content_handler;
  static_init_ = true;
}

Http3FrameHandler::~Http3FrameHandler() {
  // lsqpack_enc_cleanup(&enc_);
  // lsqpack_dec_cleanup(&dec_);
}

int Http3FrameHandler::HandleStaticContent(
    HQUIC &stream, std::unordered_map<std::string, std::string> &headers_map,
    std::string &data,
    const std::shared_ptr<Http3FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<QuicTransport> &transport_ptr) {
  std::cout << "Handling files..\n";
  auto content_handler_ptr = static_content_handler_.lock();
  if (content_handler_ptr == nullptr) {
    return ERROR;
  }

  uint64_t file_size = content_handler_ptr->FileHandler(
      headers_map[":path"], headers_map.count("accept-encoding")
                                ? headers_map.at("accept-encoding")
                                : "");

  if (file_size == 0) {
    std::cout << "Falling back to router..\n";
    return HandleRouterRequest(stream, frame_builder_ptr, transport_ptr,
                               headers_map[":method"], headers_map[":path"],
                               data);
  }

  std::string header_str = content_handler_ptr->BuildHeadersForFileTransfer(
      headers_map[":path"], file_size);

  std::unordered_map<std::string, std::string> res_headers_map =
      header_parser_.ConvertResponseToPseudoHeaders(header_str);

  std::vector<uint8_t> encoded_headers;

  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  codec_ptr->Encode(static_cast<void *>(&stream), res_headers_map,
                    encoded_headers);

  transport_ptr->Send(stream, frame_builder_ptr->BuildFrame(Frame::HEADERS, 0,
                                                            encoded_headers));

  std::cout << "Attempting to send file: " << headers_map[":path"] << "\n";
  int fd = open(headers_map[":path"].c_str(), O_RDONLY);
  if (fd == -1) {
    LogError("Opening file: " + headers_map[":path"]);
    return ERROR;
  }

  (void)transport_ptr->SendBatch(
      stream, frame_builder_ptr->BuildDataFramesFromFile(fd, file_size));

  close(fd);
  return 0;
}

int Http3FrameHandler::HandleRouterRequest(
    HQUIC &stream, const std::shared_ptr<Http3FrameBuilder> &frame_builder_ptr,
    const std::shared_ptr<QuicTransport> &transport_ptr, std::string &method,
    std::string &path, const std::string &data) {
  auto router_ptr = router_.lock();
  if (router_ptr == nullptr) {
    return ERROR;
  }

  std::string body;

  std::unordered_map<std::string, std::string> res_headers_map;

  auto opt = router_ptr->OptRouteRequest(method, path, data);
  if (opt) {
    auto &[pseudo_headers, body_ref] = *opt;
    res_headers_map = pseudo_headers;
    body = body_ref;
    res_headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  } else {
    auto [headers, body_ref] = router_ptr->RouteRequest(method, path, data);
    body = body_ref;
    res_headers_map = header_parser_.ConvertResponseToPseudoHeaders(
        std::string_view(headers));

    res_headers_map["alt-svc"] = "h3=\":4567\"; ma=86400";
  }
  std::vector<uint8_t> encoded_headers;

  auto codec_ptr = codec_.lock();
  if (codec_ptr == nullptr) {
    return ERROR;
  }

  codec_ptr->Encode(static_cast<void *>(&stream), res_headers_map,
                    encoded_headers);

  std::vector<std::vector<uint8_t>> frames;
  frames.reserve(2);

  frames.emplace_back(
      frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, encoded_headers));

  frames.emplace_back(frame_builder_ptr->BuildFrame(Frame::DATA, 0, {}, body));

  transport_ptr->SendBatch(stream, frames);
  // Fix to only send headers if body is empty
  // // Send response
  // if (body.empty()) {
  //   (void)transport_ptr->Send(
  //       ssl, frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, frame_stream,
  //       0,
  //                                          0, encoded_headers));
  // } else {
  //   std::vector<std::vector<uint8_t>> frames;
  //   frames.reserve(2);
  //   frames.emplace_back(frame_builder_ptr->BuildFrame(
  //       Frame::HEADERS, 0, frame_stream, 0, 0, encoded_headers));
  //   frames.emplace_back(frame_builder_ptr->BuildFrame(
  //       Frame::DATA, 0, frame_stream, 0, 0, {}, body));
  //
  //   (void)transport_ptr->SendBatch(ssl, frames);
  // }

  return 0;
}

int Http3FrameHandler::AnswerRequest(
    HQUIC &stream, std::unordered_map<std::string, std::string> &headers_map,
    std::string &data) {
  static constexpr std::string_view static_path = "/static/";
  static constexpr uint8_t static_path_size = static_path.size();

  auto transport_ptr = transport_.lock();
  if (transport_ptr == nullptr) {
    return ERROR;
  }
  auto frame_builder_ptr = frame_builder_.lock();
  if (frame_builder_ptr == nullptr) {
    return ERROR;
  }

  header_parser_.ValidateRequestPseudoHeaders(headers_map);

  std::string &path = headers_map[":path"];
  std::string &method = headers_map[":method"];

  // Handle static content
  if (path.size() > static_path_size && path.starts_with(static_path)) {
    return HandleStaticContent(stream, headers_map, data, frame_builder_ptr,
                               transport_ptr);
  }

  // Handle dynamic content via router
  return HandleRouterRequest(stream, frame_builder_ptr, transport_ptr, method,
                             path, data);
}

int Http3FrameHandler::ProcessFrames(HQUIC &stream,
                                     std::vector<uint8_t> &stream_buffer) {
  std::unordered_map<std::string, std::string> headers_map;
  std::string data{};

  auto iter = stream_buffer.begin();

  while (iter < stream_buffer.end()) {
    // Ensure we have enough data for a frame (frame_type + frameLength)
    if (std::distance(iter, stream_buffer.end()) < 3) {
      break;
    }

    // Read the frame type
    uint64_t frame_type = ReadVarint(iter, stream_buffer.end());

    // Read the frame length
    uint64_t payload_size = ReadVarint(iter, stream_buffer.end());

    // Ensure the payload doesn't exceed the bounds of the buffer
    // if (static_cast<uint64_t>(std::distance(iter, stream_buffer.end())) <
    //     payload_size) {
    //   LogError("Payload exceeds buffer bounds");
    //   break;
    // }

    ProcessFrame(stream, iter, frame_type, payload_size, headers_map, data);

    iter += payload_size;
  }

  // Should not happen but just in case
  if (iter < stream_buffer.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    stream_buffer.end() - iter);
    std::cout << std::endl;
  }

#ifdef ECHO
  std::cout << "HTTP3 Request: \n";
  for (auto &[key, value] : headers_map) {
    std::cout << key << ": " << value << "\n";
  }
  std::cout << data << std::endl;
#endif

  if (is_server_) {
    AnswerRequest(stream, headers_map, data);
  }

  return 0;
}

int Http3FrameHandler::ProcessFrame(
    HQUIC &stream, std::vector<uint8_t>::iterator &iter, uint64_t frame_type,
    uint64_t payload_size,
    std::unordered_map<std::string, std::string> &headers_map,
    std::string &data) {
  switch (frame_type) {
    case Frame::DATA:
#ifdef HTTP3_DEBUG
      std::cout << "[strm][" << stream << "] Received DATA frame\n";
#endif
      // Data might have been transmitted over multiple frames
      data += std::string(iter, iter + payload_size);
      break;

    case Frame::HEADERS:
#ifdef HTTP3_DEBUG
      std::cout << "[strm][" << stream << "] Received Headers frame\n";
#endif

      {
        std::vector<uint8_t> encoded_headers(iter, iter + payload_size);

        // QuicClient::QPACK_DecodeHeaders(Stream, encoded_headers);

        auto codec_ptr = codec_.lock();
        if (codec_ptr == nullptr) {
          return ERROR;
        }

        // Kinda inefficient could change to get start and end ptr of the
        // encoded headers in the stream_buffer
        codec_ptr->Decode(static_cast<void *>(&stream), encoded_headers,
                          headers_map);
      }

      break;

    default:
      std::cout << "[strm][" << stream << "] Unknown frame type: 0x" << std::hex
                << frame_type << std::dec << "\n";
      break;
  }

  return 0;
}
