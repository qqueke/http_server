// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/http3_frame_builder.h"

#include <string>
#include <vector>

#include "../include/log.h"

static void EncodeVarint(std::vector<uint8_t> &buffer, uint64_t value) {
  if (value <= 63) {
    buffer.emplace_back(static_cast<uint8_t>(value));
  } else if (value <= 16383) {
    buffer.emplace_back(static_cast<uint8_t>((value >> 8) | 0x40));
    buffer.emplace_back(static_cast<uint8_t>(value & 0xFF));
  } else if (value <= 1073741823) {
    buffer.emplace_back(static_cast<uint8_t>((value >> 24) | 0x80));
    buffer.emplace_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.emplace_back(static_cast<uint8_t>(value & 0xFF));
  } else if (value <= 4611686018427387903) {
    buffer.emplace_back(static_cast<uint8_t>((value >> 56) | 0xC0));
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
Http3FrameBuilder::BuildDataFrame(std::vector<uint8_t> bytes,
                                  uint32_t payload_size) {
  // Construct the frame header for Headers
  uint8_t frame_type = Frame::DATA;

  // Header Frame : Type, Length
  std::vector<uint8_t> frame_header;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frame_header, frame_type);
  // Encode the frame length (size of the payload)
  EncodeVarint(frame_header, payload_size);

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payload_size);
  memcpy(framePayload.data(), bytes.data(), payload_size);

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

std::vector<std::vector<uint8_t>>
Http3FrameBuilder::BuildDataFramesFromFile(int fd, uint64_t file_size) {
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

    frames.emplace_back(BuildDataFrame(bytes, read_bytes));
  }

  return frames;
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

std::vector<uint8_t> Http3FrameBuilder::BuildSettingsFrame() { return {}; }

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
