#include "http2_frame_builder.h"

#include <array>
#include <iostream>

#include "utils.h"

static void EncodeVarint(std::vector<uint8_t> &buffer, uint64_t value) {
  if (value <= 63) { // Fit in 1 byte
    buffer.emplace_back(static_cast<uint8_t>(value));
  } else if (value <= 16383) { // Fit in 2 bytes
    buffer.emplace_back(
        static_cast<uint8_t>((value >> 8) | 0x40));          // Set prefix 01
    buffer.emplace_back(static_cast<uint8_t>(value & 0xFF)); // Remaining 8 bits
  } else if (value <= 1073741823) {                          // Fit in 4 bytes
    buffer.emplace_back(
        static_cast<uint8_t>((value >> 24) | 0x80)); // Set prefix 10
    buffer.emplace_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>(value & 0xFF));
  } else if (value <= 4611686018427387903) { // Fit in 8 bytes
    buffer.emplace_back(
        static_cast<uint8_t>((value >> 56) | 0xC0)); // Set prefix 11
    buffer.emplace_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>(value & 0xFF));
  }
}

std::vector<uint8_t> Http2FrameBuilder::BuildFrame(
    Frame type, uint8_t frame_flags, uint32_t stream_id, uint32_t error_code,
    uint32_t increment, const std::vector<uint8_t> &encoded_headers,
    const std::string &data) {
  switch (type) {
  case Frame::DATA:
    return BuildDataFrame(data, stream_id);
  case Frame::HEADERS:
    return BuildHeaderFrame(encoded_headers, stream_id);
  case Frame::GOAWAY:
    return BuildGoAwayFrame(stream_id, error_code);
  case Frame::SETTINGS:
    return BuildSettingsFrame(frame_flags);
  case Frame::RST_STREAM:
    return BuildRstStreamFrame(stream_id, error_code);
  case Frame::WINDOW_UPDATE:
    return BuildWindowUpdateFrame(stream_id, increment);
  default:
    return {};
  }
}

std::vector<uint8_t>
Http3FrameBuilder::BuildFrame(Frame type, uint32_t stream_id,
                              const std::vector<uint8_t> &encoded_headers,
                              const std::string &data) {
  switch (type) {
  case Frame::DATA:
    return BuildDataFrame(data);
  case Frame::HEADERS:
    return BuildHeaderFrame(encoded_headers);
  case Frame::GOAWAY:
    return BuildGoAwayFrame(stream_id);
  case Frame::SETTINGS:
    return BuildSettingsFrame();
  default:
    return {};
  }
}

std::vector<uint8_t> Http2FrameBuilder::BuildDataFrame(const std::string &data,
                                                       uint32_t stream_id) {
  uint8_t frame_type = Frame::DATA;
  uint8_t flags = HTTP2Flags::END_STREAM_FLAG;
  uint32_t payload_size = data.size();
  uint32_t total_frame_size = FRAME_HEADER_LENGTH + payload_size;

  std::vector<uint8_t> frame(total_frame_size);

  frame[0] = (payload_size >> 16) & 0xFF;
  frame[1] = (payload_size >> 8) & 0xFF;
  frame[2] = payload_size & 0xFF;

  frame[3] = frame_type;

  frame[4] = flags;

  frame[5] = (stream_id >> 24) & 0xFF;
  frame[6] = (stream_id >> 16) & 0xFF;
  frame[7] = (stream_id >> 8) & 0xFF;
  frame[8] = stream_id & 0xFF;

  memcpy(frame.data() + FRAME_HEADER_LENGTH, data.data(), payload_size);

  return frame;
}

std::vector<uint8_t>
Http3FrameBuilder::BuildDataFrame(const std::string &data) {
  // Construct the frame header for Headers
  uint8_t frame_type = Frame::DATA;
  uint32_t payload_size = data.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frame_header;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frame_header, frame_type);
  // Encode the frame length (size of the payload)
  EncodeVarint(frame_header, payload_size);

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payload_size);
  memcpy(framePayload.data(), data.c_str(), payload_size);

  // Combine the Frame Header and Payload into one buffer
  uint32_t total_frame_size = frame_header.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> frame(total_frame_size);
  memcpy(frame.data(), frame_header.data(), frame_header.size());
  memcpy(frame.data() + frame_header.size(), framePayload.data(), payload_size);

  // std::vector<uint8_t> frame;
  // frame.reserve();
  // // Encode the frame type (0x01 for HEADERS frame)
  // EncodeVarint(frame, frame_type);
  // // Encode the frame length (size of the payload)
  // EncodeVarint(frame, payload_size);
  //
  // frame.insert(frame.end(), data.begin(), data.end());

  return frame;
}

std::vector<uint8_t>
Http2FrameBuilder::BuildHeaderFrame(const std::vector<uint8_t> &encoded_headers,
                                    uint32_t stream_id) {
  // Construct the frame header for Headers
  uint8_t frame_type = Frame::HEADERS;
  uint32_t payload_size = encoded_headers.size();
  uint8_t flags = HTTP2Flags::END_HEADERS_FLAG;
  // flags |= (1 << 0);

  uint32_t total_frame_size = FRAME_HEADER_LENGTH + payload_size;

  std::vector<uint8_t> frame(total_frame_size);

  frame[0] = (payload_size >> 16) & 0xFF;
  frame[1] = (payload_size >> 8) & 0xFF;
  frame[2] = payload_size & 0xFF;

  frame[3] = frame_type;

  frame[4] = flags;

  frame[5] = (stream_id >> 24) & 0xFF;
  frame[6] = (stream_id >> 16) & 0xFF;
  frame[7] = (stream_id >> 8) & 0xFF;
  frame[8] = stream_id & 0xFF;

  memcpy(frame.data() + FRAME_HEADER_LENGTH, encoded_headers.data(),
         payload_size);

  return frame;
}

std::vector<uint8_t> Http3FrameBuilder::BuildHeaderFrame(
    const std::vector<uint8_t> &encoded_headers) {
  uint8_t frame_type = Frame::HEADERS;
  size_t payload_size = encoded_headers.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frame_header;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frame_header, frame_type);
  // Encode the frame length (size of the payload)
  EncodeVarint(frame_header, payload_size);

  // Frame payload for Headers
  // std::vector<uint8_t> framePayload(payload_size);
  // memcpy(framePayload.data(), encoded_headers.c_str(), payload_size);

  // Combine the Frame Header and Payload into one buffer
  size_t total_frame_size = frame_header.size() + payload_size;

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> frame(total_frame_size);
  frame.resize(total_frame_size);
  memcpy(frame.data(), frame_header.data(), frame_header.size());
  memcpy(frame.data() + frame_header.size(), encoded_headers.data(),
         payload_size);

  return frame;
}

std::vector<uint8_t>
Http2FrameBuilder::BuildSettingsFrame(uint8_t frame_flags) {
  static constexpr std::array<std::pair<uint16_t, uint32_t>, 4> settings = {
      std::make_pair(HTTP2Settings::MAX_CONCURRENT_STREAMS, 100),
      std::make_pair(HTTP2Settings::INITIAL_WINDOW_SIZE, 65535),
      std::make_pair(HTTP2Settings::MAX_FRAME_SIZE, 16384),
      std::make_pair(HTTP2Settings::MAX_HEADER_LIST_SIZE, 0xFFFFFFFF),
  };

  uint8_t frame_type = Frame::SETTINGS;
  uint8_t stream_id = 0;
  uint32_t payload_size = 0;
  if (!isFlagSet(frame_flags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
    payload_size = settings.size() * 6;
  }

  uint32_t total_frame_size = FRAME_HEADER_LENGTH + payload_size;

  std::vector<uint8_t> frame(total_frame_size);

  // Frame header
  frame[0] = (payload_size >> 16) & 0xFF;
  frame[1] = (payload_size >> 8) & 0xFF;
  frame[2] = payload_size & 0xFF;
  frame[3] = frame_type;
  frame[4] = frame_flags;
  frame[5] = (stream_id >> 24) & 0xFF;
  frame[6] = (stream_id >> 16) & 0xFF;
  frame[7] = (stream_id >> 8) & 0xFF;
  frame[8] = stream_id & 0xFF;

  if (payload_size == 0) {
    return frame;
  }

  uint32_t offset = FRAME_HEADER_LENGTH;
  for (const auto &setting : settings) {
    const uint16_t &setting_id = setting.first;
    const uint32_t &setting_val = setting.second;

    // Write the Setting ID (2 bytes)
    frame[offset] = (setting_id >> 8) & 0xFF;
    frame[offset + 1] = setting_id & 0xFF;

    // Write the Setting Value (4 bytes)
    frame[offset + 2] = (setting_val >> 24) & 0xFF;
    frame[offset + 3] = (setting_val >> 16) & 0xFF;
    frame[offset + 4] = (setting_val >> 8) & 0xFF;
    frame[offset + 5] = setting_val & 0xFF;

    offset += 6;
  }

  return frame;
}

std::vector<uint8_t> Http3FrameBuilder::BuildSettingsFrame() { return {}; }

std::vector<uint8_t>
Http2FrameBuilder::BuildRstStreamFrame(uint32_t stream_id,
                                       uint32_t error_code) {
  uint8_t frame_type = Frame::RST_STREAM;
  uint8_t frame_flags = HTTP2Flags::NONE_FLAG;
  uint8_t payload_size = 4;
  uint32_t total_frame_size = FRAME_HEADER_LENGTH + payload_size;

  std::vector<uint8_t> frame(total_frame_size);

  // Frame header
  frame[0] = (payload_size >> 16) & 0xFF;
  frame[1] = (payload_size >> 8) & 0xFF;
  frame[2] = payload_size & 0xFF;
  frame[3] = frame_type;
  frame[4] = frame_flags;
  frame[5] = (stream_id >> 24) & 0xFF;
  frame[6] = (stream_id >> 16) & 0xFF;
  frame[7] = (stream_id >> 8) & 0xFF;
  frame[8] = stream_id & 0xFF;

  // Frame payload
  // Error Code
  frame[FRAME_HEADER_LENGTH] = (error_code >> 24) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 1] = (error_code >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (error_code >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = error_code & 0xFF;

  // Size must be set accordingly
  return frame;
}

std::vector<uint8_t> Http2FrameBuilder::BuildGoAwayFrame(uint32_t stream_id,
                                                         uint32_t error_code) {
  uint8_t frame_type = Frame::GOAWAY;
  uint8_t frame_flags = HTTP2Flags::NONE_FLAG;
  uint8_t payload_size = 8;
  uint32_t total_frame_size = FRAME_HEADER_LENGTH + payload_size;

  std::vector<uint8_t> frame(total_frame_size);

  // Frame header
  frame[0] = (payload_size >> 16) & 0xFF;
  frame[1] = (payload_size >> 8) & 0xFF;
  frame[2] = payload_size & 0xFF;
  frame[3] = frame_type;
  frame[4] = frame_flags;
  frame[5] = (stream_id >> 24) & 0xFF;
  frame[6] = (stream_id >> 16) & 0xFF;
  frame[7] = (stream_id >> 8) & 0xFF;
  frame[8] = stream_id & 0xFF;

  // Frame payload
  // Last processed stream id
  frame[FRAME_HEADER_LENGTH] = (stream_id >> 24) & 0x7F;
  frame[FRAME_HEADER_LENGTH + 1] = (stream_id >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (stream_id >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = stream_id & 0xFF;

  // Error Code
  frame[FRAME_HEADER_LENGTH + 4] = (error_code >> 24) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 5] = (error_code >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 6] = (error_code >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 7] = error_code & 0xFF;

  // Size must be set accordingly
  return frame;
}

std::vector<uint8_t> Http3FrameBuilder::BuildGoAwayFrame(uint32_t stream_id) {
  uint8_t frame_type = Frame::GOAWAY;

  uint32_t payload_size = 0;

  // Header Frame : Type, Length
  std::vector<uint8_t> frame_header;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frame_header, frame_type);
  // Encode the frame length (size of the payload)
  EncodeVarint(frame_header, payload_size);

  return frame_header;
}

std::vector<uint8_t>
Http2FrameBuilder::BuildWindowUpdateFrame(uint32_t stream_id,
                                          uint32_t increment) {
  // Construct the frame header for Headers
  uint8_t frame_type = Frame::WINDOW_UPDATE;
  uint8_t payload_size = 4;
  uint32_t total_frame_size = FRAME_HEADER_LENGTH + payload_size;

  std::vector<uint8_t> frame(total_frame_size);

  frame[0] = (payload_size >> 16) & 0xFF;
  frame[1] = (payload_size >> 8) & 0xFF;
  frame[2] = payload_size & 0xFF;

  frame[3] = frame_type;

  frame[4] = HTTP2Flags::NONE_FLAG;

  frame[5] = (stream_id >> 24) & 0xFF;
  frame[6] = (stream_id >> 16) & 0xFF;
  frame[7] = (stream_id >> 8) & 0xFF;
  frame[8] = stream_id & 0xFF;

  frame[FRAME_HEADER_LENGTH] = (increment >> 24) & 0x7F;
  frame[FRAME_HEADER_LENGTH + 1] = (increment >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (stream_id >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = increment & 0xFF;

  return frame;
}
