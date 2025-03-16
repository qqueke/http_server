// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/http2_frame_builder.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "../include/log.h"
#include "../include/utils.h"

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

std::vector<uint8_t> Http2FrameBuilder::BuildDataFrame(
    const std::vector<uint8_t> &bytes, uint32_t payload_size,
    uint32_t stream_id, uint8_t frame_flags) {
  uint8_t frame_type = Frame::DATA;
  // uint8_t flags = HTTP2Flags::END_STREAM_FLAG;
  uint32_t total_frame_size = FRAME_HEADER_LENGTH + payload_size;

  std::vector<uint8_t> frame(total_frame_size);

  frame[0] = (payload_size >> 16) & 0xFF;
  frame[1] = (payload_size >> 8) & 0xFF;
  frame[2] = payload_size & 0xFF;
  frame[3] = frame_type;

  frame[4] = frame_flags;

  frame[5] = (stream_id >> 24) & 0xFF;
  frame[6] = (stream_id >> 16) & 0xFF;
  frame[7] = (stream_id >> 8) & 0xFF;
  frame[8] = stream_id & 0xFF;

  memcpy(frame.data() + FRAME_HEADER_LENGTH, bytes.data(), payload_size);

  return frame;
}

std::vector<uint8_t> Http2FrameBuilder::BuildDataFrameFromFile(
    int fd, uint64_t file_size, uint32_t stream_id) {
  if (file_size > MAX_PAYLOAD_FRAME_SIZE) {
    LogError("File is too big. Call BuildDataFramesFromFile instead");
    return {};
  }

  std::vector<uint8_t> bytes(MAX_PAYLOAD_FRAME_SIZE);

  int read_bytes = 1;
  uint64_t total_bytes_read = 0;
  while (read_bytes > 0) {
    read_bytes =
        read(fd, bytes.data() + total_bytes_read, MAX_PAYLOAD_FRAME_SIZE);

    if (read_bytes < 0) {
      LogError("Reading from file descriptor");
      return {};
    }
    if (read_bytes == 0) {
      break;
    }

    total_bytes_read += read_bytes;
  }

  return BuildDataFrame(bytes, total_bytes_read, stream_id,
                        HTTP2Flags::END_STREAM_FLAG);
}

std::vector<std::vector<uint8_t>> Http2FrameBuilder::BuildDataFramesFromFile(
    int fd, uint64_t file_size, uint32_t stream_id) {
  std::vector<uint8_t> bytes(MAX_PAYLOAD_FRAME_SIZE);

  uint32_t n_required_frames = (file_size / MAX_PAYLOAD_FRAME_SIZE) + 1;
  std::vector<std::vector<uint8_t>> frames;
  frames.reserve(n_required_frames);

  int read_bytes = 1;
  uint64_t total_bytes_read = 0;
  while (read_bytes > 0) {
    read_bytes = read(fd, bytes.data(), MAX_PAYLOAD_FRAME_SIZE);

    if (read_bytes < 0) {
      LogError("Reading from file descriptor");
      return {};
    }
    if (read_bytes == 0) {
      break;
    }

    total_bytes_read += read_bytes;

    frames.emplace_back(BuildDataFrame(bytes, read_bytes, stream_id,
                                       (total_bytes_read >= file_size)
                                           ? HTTP2Flags::END_STREAM_FLAG
                                           : HTTP2Flags::NONE_FLAG));
  }

  return frames;
}

std::vector<uint8_t> Http2FrameBuilder::BuildHeaderFrame(
    const std::vector<uint8_t> &encoded_headers, uint32_t stream_id) {
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

std::vector<uint8_t> Http2FrameBuilder::BuildSettingsFrame(
    uint8_t frame_flags) {
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

std::vector<uint8_t> Http2FrameBuilder::BuildRstStreamFrame(
    uint32_t stream_id, uint32_t error_code) {
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

std::vector<uint8_t> Http2FrameBuilder::BuildWindowUpdateFrame(
    uint32_t stream_id, uint32_t increment) {
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
