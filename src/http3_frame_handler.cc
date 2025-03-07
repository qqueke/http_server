#include "http3_frame_handler.h"

#include <iostream>

#include "common.h"
#include "log.h"

static uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                           const std::vector<uint8_t>::iterator &end) {
  // Check if there's enough data for at least the first byte
  if (iter + 1 >= end) {
    LogError("Buffer overflow in ReadVarint");
    return ERROR;
  }

  // Read the first byte
  uint64_t value = *iter++;
  uint8_t prefix =
      value >> 6; // Get the prefix to determine the length of the varint
  size_t length = 1 << prefix; // 1, 2, 4, or 8 bytes

  value &= 0x3F; // Mask out the 2 most significant bits

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

Http3FrameHandler::Http3FrameHandler(
    const std::shared_ptr<QuicTransport> &quic_transport,
    const std::shared_ptr<Http3FrameBuilder> &http2_frame_builder,
    const std::shared_ptr<QpackCodec> &qpack_codec,
    const std::shared_ptr<Router> &router)
    : transport_(quic_transport), frame_builder_(http2_frame_builder),
      codec_(qpack_codec), router_(router), is_server_(true) {
  // lsqpack_enc_init(&enc_);
  // lsqpack_dec_init(&dec_);
}

Http3FrameHandler::Http3FrameHandler(
    const std::shared_ptr<QuicTransport> &quic_transport,
    const std::shared_ptr<Http3FrameBuilder> &http2_frame_builder,
    const std::shared_ptr<QpackCodec> &qpack_codec)
    : transport_(quic_transport), frame_builder_(http2_frame_builder),
      codec_(qpack_codec), is_server_(false) {
  // lsqpack_enc_init(&enc_);
  // lsqpack_dec_init(&dec_);
}

Http3FrameHandler::~Http3FrameHandler() {
  // lsqpack_enc_cleanup(&enc_);
  // lsqpack_dec_cleanup(&dec_);
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
    if (std::distance(iter, stream_buffer.end()) < payload_size) {
      LogError("Payload exceeds buffer bounds");
      break;
    }

    ProcessFrame(stream, iter, frame_type, payload_size, headers_map, data);

    iter += payload_size;
  }
  // std::cout << headers << data << "\n";

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < stream_buffer.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    stream_buffer.end() - iter);
    std::cout << std::endl;
  }

  std::cout << "HTTP3 Request: \n";
  for (auto &[key, value] : headers_map) {
    std::cout << key << ": " << value << "\n";
  }
  std::cout << data << std::endl;

  if (is_server_) {
    ValidatePseudoHeadersTmp(headers_map);

    auto router_ptr = router_.lock();
    if (router_ptr == nullptr) {
      return ERROR;
    }

    // Route Request
    auto [headers, body] =
        router_ptr->RouteRequest(headers_map[":method"], headers_map[":path"]);

    std::unordered_map<std::string, std::string> res_headers_map;
    res_headers_map.reserve(2);

    HttpCore::RespHeaderToPseudoHeader(headers, res_headers_map);

    std::vector<uint8_t> encoded_headers;

    // uint64_t stream_id{};
    // auto len = (uint32_t)sizeof(stream_id);
    //
    // if (QUIC_FAILED(ms_quic_->GetParam(Stream, QUIC_PARAM_STREAM_ID,
    // &len,
    //                                  &stream_id))) {
    //   LogError("Failed to acquire stream id");
    // }
    auto codec_ptr = codec_.lock();
    if (codec_ptr == nullptr) {
      return ERROR;
    }

    codec_ptr->Encode(static_cast<void *>(&stream), res_headers_map,
                      encoded_headers);
    // HttpCore::QPACK_EncodeHeaders(stream_id, headers_map,
    // encoded_headers);

    auto frame_builder_ptr = frame_builder_.lock();
    if (frame_builder_ptr == nullptr) {
      return ERROR;
    }

    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);

    frames.emplace_back(
        frame_builder_ptr->BuildFrame(Frame::HEADERS, 0, encoded_headers));

    frames.emplace_back(
        frame_builder_ptr->BuildFrame(Frame::DATA, 0, {}, body));

    auto transport_ptr = transport_.lock();
    if (transport_ptr == nullptr) {
      return ERROR;
    }

    transport_ptr->SendBatch(stream, frames);
    // HttpCore::HTTP3_SendFrames(Stream, frames);
  }

  return 0;
}

int Http3FrameHandler::ProcessFrame(
    HQUIC &stream, std::vector<uint8_t>::iterator &iter, uint64_t frame_type,
    uint64_t payload_size,
    std::unordered_map<std::string, std::string> &headers_map,
    std::string &data) {
  switch (frame_type)

  {
  case Frame::DATA: // DATA frame
    // std::cout << "[strm][" << Stream << "] Received DATA frame\n";
    // Data might have been transmitted over multiple frames
    data += std::string(iter, iter + payload_size);
    break;

  case Frame::HEADERS:
    // std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

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

  default: // Unknown frame type
    std::cout << "[strm][" << stream << "] Unknown frame type: 0x" << std::hex
              << frame_type << std::dec << "\n";
    break;
  }

  return 0;
}
