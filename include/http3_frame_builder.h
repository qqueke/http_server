// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file http3_frame_builder.h
 * @brief Provides functionality to build HTTP/3 frames.
 *
 * This file defines the `Http3FrameBuilder` class that contains methods to
 * construct various HTTP/3 frames, including data frames, header frames, and
 * control frames such as GOAWAY and SETTINGS frames.
 */
#ifndef INCLUDE_HTTP3_FRAME_BUILDER_H_
#define INCLUDE_HTTP3_FRAME_BUILDER_H_

#include <vector>

#include "utils.h"

/**
 * @class Http3FrameBuilder
 * @brief Class to build various HTTP/3 frames.
 *
 * The `Http3FrameBuilder` class provides methods for constructing HTTP/3 frames
 * such as data frames, header frames, and control frames (e.g., GOAWAY,
 * SETTINGS frames). It allows the construction of frames with specified stream
 * IDs, payloads, and other frame-specific details.
 */
class Http3FrameBuilder {
 public:
  /**
   * @brief Builds a generic HTTP/3 frame.
   *
   * This method builds a generic HTTP/3 frame with the provided parameters. It
   * can be used for various types of frames, including data, header, and
   * control frames.
   *
   * @param type The type of the HTTP/3 frame (e.g., DATA, HEADERS).
   * @param stream_id The stream ID associated with the frame (optional, default
   * is 0).
   * @param encoded_headers The encoded headers for a HEADERS frame (optional,
   * default is empty).
   * @param data The payload data for the frame (optional, default is empty).
   * @return A vector of bytes representing the constructed HTTP/3 frame.
   */
  std::vector<uint8_t> BuildFrame(
      Frame type, uint32_t stream_id = 0,
      const std::vector<uint8_t> &encoded_headers = {},
      const std::string &data = "");

  /**
   * @brief Builds a DATA frame.
   *
   * This method builds an HTTP/3 DATA frame with the provided payload data.
   *
   * @param data The payload data for the DATA frame.
   * @return A vector of bytes representing the constructed DATA frame.
   */
  std::vector<uint8_t> BuildDataFrame(const std::string &data);

  /**
   * @brief Builds a DATA frame from the given byte buffer.
   *
   * This method builds a DATA frame using the provided byte buffer as the
   * payload.
   *
   * @param bytes A vector of bytes to be included in the DATA frame payload.
   * @param payload_size The size of the payload in the DATA frame.
   * @return A vector of bytes representing the constructed DATA frame.
   */
  std::vector<uint8_t> BuildDataFrame(std::vector<uint8_t> bytes,
                                      uint32_t payload_size);

  /**
   * @brief Builds multiple DATA frames from a file.
   *
   * This method builds multiple HTTP/3 DATA frames from a file, reading data
   * from the given file descriptor and chunking the data based on the file
   * size.
   *
   * @param fd The file descriptor to read data from.
   * @param file_size The total size of the file to be split into multiple DATA
   * frames.
   * @return A vector of vectors of bytes, each representing a constructed DATA
   * frame.
   */
  std::vector<std::vector<uint8_t>> BuildDataFramesFromFile(int fd,
                                                            uint64_t file_size);

  /**
   * @brief Builds a HEADER frame.
   *
   * This method builds an HTTP/3 HEADER frame with the provided encoded
   * headers.
   *
   * @param encoded_headers The encoded headers to be included in the HEADER
   * frame.
   * @return A vector of bytes representing the constructed HEADER frame.
   */
  std::vector<uint8_t> BuildHeaderFrame(
      const std::vector<uint8_t> &encoded_headers);

  /**
   * @brief Builds a GOAWAY frame.
   *
   * This method builds an HTTP/3 GOAWAY frame with the specified stream ID.
   *
   * @param stream_id The stream ID to associate with the GOAWAY frame.
   * @return A vector of bytes representing the constructed GOAWAY frame.
   */
  std::vector<uint8_t> BuildGoAwayFrame(uint32_t stream_id);

  /**
   * @brief Builds a SETTINGS frame.
   *
   * This method builds an HTTP/3 SETTINGS frame.
   *
   * @return A vector of bytes representing the constructed SETTINGS frame.
   */
  std::vector<uint8_t> BuildSettingsFrame();
};

#endif  // HTTP3_FRAME_BUILDER_H
