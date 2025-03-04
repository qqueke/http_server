#include "framebuilder.hpp"

#include <array>
#include <iostream>

#include "utils.hpp"

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

std::vector<uint8_t>
Http2FrameBuilder::BuildFrame(Frame type, uint8_t frameFlags, uint32_t streamId,
                              uint32_t errorCode, uint32_t increment,
                              const std::vector<uint8_t> &encodedHeaders,
                              const std::string &data) {
  switch (type) {
  case Frame::DATA:
    return BuildDataFrame(data, streamId);
  case Frame::HEADERS:
    return BuildHeaderFrame(encodedHeaders, streamId);
  case Frame::GOAWAY:
    return BuildGoAwayFrame(streamId, errorCode);
  case Frame::SETTINGS:
    return BuildSettingsFrame(frameFlags);
  case Frame::RST_STREAM:
    return BuildRstStreamFrame(streamId, errorCode);
  case Frame::WINDOW_UPDATE:
    return BuildWindowUpdateFrame(streamId, increment);
  default:
    return {};
  }
}

std::vector<uint8_t>
Http3FrameBuilder::BuildFrame(Frame type, uint32_t streamId,
                              const std::vector<uint8_t> &encodedHeaders,
                              const std::string &data) {
  switch (type) {
  case Frame::DATA:
    return BuildDataFrame(data);
  case Frame::HEADERS:
    return BuildHeaderFrame(encodedHeaders);
  case Frame::GOAWAY:
    return BuildGoAwayFrame(streamId);
  case Frame::SETTINGS:
    return BuildSettingsFrame();
  default:
    return {};
  }
}

std::vector<uint8_t> Http2FrameBuilder::BuildDataFrame(const std::string &data,
                                                       uint32_t streamId) {
  uint8_t frameType = Frame::DATA;
  uint8_t flags = HTTP2Flags::END_STREAM_FLAG;
  uint32_t payloadLength = data.size();
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;

  frame[3] = frameType;

  frame[4] = flags;

  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  memcpy(frame.data() + FRAME_HEADER_LENGTH, data.data(), payloadLength);

  return frame;
}

std::vector<uint8_t>
Http3FrameBuilder::BuildDataFrame(const std::string &data) {
  // Construct the frame header for Headers
  uint8_t frameType = Frame::DATA;
  uint32_t payloadLength = data.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType);
  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength);

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payloadLength);
  memcpy(framePayload.data(), data.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  uint32_t totalFrameSize = frameHeader.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> frame(totalFrameSize);
  memcpy(frame.data(), frameHeader.data(), frameHeader.size());
  memcpy(frame.data() + frameHeader.size(), framePayload.data(), payloadLength);

  // std::vector<uint8_t> frame;
  // frame.reserve();
  // // Encode the frame type (0x01 for HEADERS frame)
  // EncodeVarint(frame, frameType);
  // // Encode the frame length (size of the payload)
  // EncodeVarint(frame, payloadLength);
  //
  // frame.insert(frame.end(), data.begin(), data.end());

  return frame;
}

std::vector<uint8_t>
Http2FrameBuilder::BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders,
                                    uint32_t streamId) {
  // Construct the frame header for Headers
  uint8_t frameType = Frame::HEADERS;
  uint32_t payloadLength = encodedHeaders.size();
  uint8_t flags = HTTP2Flags::END_HEADERS_FLAG;
  // flags |= (1 << 0);

  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;

  frame[3] = frameType;

  frame[4] = flags;

  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  memcpy(frame.data() + FRAME_HEADER_LENGTH, encodedHeaders.data(),
         payloadLength);

  return frame;
}

std::vector<uint8_t> Http3FrameBuilder::BuildHeaderFrame(
    const std::vector<uint8_t> &encodedHeaders) {
  uint8_t frameType = Frame::HEADERS;
  size_t payloadLength = encodedHeaders.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType);
  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength);

  // Frame payload for Headers
  // std::vector<uint8_t> framePayload(payloadLength);
  // memcpy(framePayload.data(), encodedHeaders.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + payloadLength;

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> headerFrame(totalFrameSize);
  headerFrame.resize(totalFrameSize);
  memcpy(headerFrame.data(), frameHeader.data(), frameHeader.size());
  memcpy(headerFrame.data() + frameHeader.size(), encodedHeaders.data(),
         payloadLength);

  return headerFrame;
}

std::vector<uint8_t> Http2FrameBuilder::BuildSettingsFrame(uint8_t frameFlags) {
  static constexpr std::array<std::pair<uint16_t, uint32_t>, 4> settings = {
      std::make_pair(HTTP2Settings::MAX_CONCURRENT_STREAMS, 100),
      std::make_pair(HTTP2Settings::INITIAL_WINDOW_SIZE, 65535),
      std::make_pair(HTTP2Settings::MAX_FRAME_SIZE, 16384),
      std::make_pair(HTTP2Settings::MAX_HEADER_LIST_SIZE, 0xFFFFFFFF),
  };

  uint8_t frameType = Frame::SETTINGS;
  uint8_t streamId = 0;
  uint32_t payloadLength = 0;
  if (!isFlagSet(frameFlags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
    payloadLength = settings.size() * 6;
  }

  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  // Frame header
  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;
  frame[3] = frameType;
  frame[4] = frameFlags;
  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  if (payloadLength == 0) {
    return frame;
  }

  uint32_t offset = FRAME_HEADER_LENGTH;
  for (const auto &setting : settings) {
    const uint16_t &settingId = setting.first;
    const uint32_t &settingValue = setting.second;

    // Write the Setting ID (2 bytes)
    frame[offset] = (settingId >> 8) & 0xFF;
    frame[offset + 1] = settingId & 0xFF;

    // Write the Setting Value (4 bytes)
    frame[offset + 2] = (settingValue >> 24) & 0xFF;
    frame[offset + 3] = (settingValue >> 16) & 0xFF;
    frame[offset + 4] = (settingValue >> 8) & 0xFF;
    frame[offset + 5] = settingValue & 0xFF;

    offset += 6;
  }

  return frame;
}

std::vector<uint8_t> Http3FrameBuilder::BuildSettingsFrame() { return {}; }

std::vector<uint8_t>
Http2FrameBuilder::BuildRstStreamFrame(uint32_t streamId, uint32_t errorCode) {
  uint8_t frameType = Frame::RST_STREAM;
  uint8_t frameFlags = HTTP2Flags::NONE_FLAG;
  uint8_t payloadLength = 4;
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  // Frame header
  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;
  frame[3] = frameType;
  frame[4] = frameFlags;
  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  // Frame payload
  // Error Code
  frame[FRAME_HEADER_LENGTH] = (errorCode >> 24) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 1] = (errorCode >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (errorCode >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = errorCode & 0xFF;

  // Size must be set accordingly
  return frame;
}

std::vector<uint8_t> Http2FrameBuilder::BuildGoAwayFrame(uint32_t streamId,
                                                         uint32_t errorCode) {
  uint8_t frameType = Frame::GOAWAY;
  uint8_t frameFlags = HTTP2Flags::NONE_FLAG;
  uint8_t payloadLength = 8;
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  // Frame header
  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;
  frame[3] = frameType;
  frame[4] = frameFlags;
  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  // Frame payload
  // Last processed stream id
  frame[FRAME_HEADER_LENGTH] = (streamId >> 24) & 0x7F;
  frame[FRAME_HEADER_LENGTH + 1] = (streamId >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (streamId >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = streamId & 0xFF;

  // Error Code
  frame[FRAME_HEADER_LENGTH + 4] = (errorCode >> 24) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 5] = (errorCode >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 6] = (errorCode >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 7] = errorCode & 0xFF;

  // Size must be set accordingly
  return frame;
}

std::vector<uint8_t> Http3FrameBuilder::BuildGoAwayFrame(uint32_t streamId) {
  uint8_t frameType = Frame::GOAWAY;

  uint32_t payloadLength = 0;

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType);
  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength);

  return frameHeader;
}

std::vector<uint8_t>
Http2FrameBuilder::BuildWindowUpdateFrame(uint32_t streamId,
                                          uint32_t increment) {
  // Construct the frame header for Headers
  uint8_t frameType = Frame::WINDOW_UPDATE;
  uint8_t payloadLength = 4;
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;

  frame[3] = frameType;

  frame[4] = HTTP2Flags::NONE_FLAG;

  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  frame[FRAME_HEADER_LENGTH] = (increment >> 24) & 0x7F;
  frame[FRAME_HEADER_LENGTH + 1] = (increment >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (streamId >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = increment & 0xFF;

  return frame;
}
