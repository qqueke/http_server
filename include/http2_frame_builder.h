// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file http2_frame_builder.h
 * @brief Provides the functionality to build HTTP/2 frames.
 *
 * This file defines the `Http2FrameBuilder` class that contains methods for
 * constructing different types of HTTP/2 frames, such as data frames, header
 * frames, and control frames.
 */
#ifndef INCLUDE_HTTP2_FRAME_BUILDER_H_
#define INCLUDE_HTTP2_FRAME_BUILDER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "utils.h"

/**
 * @class Http2FrameBuilder
 * @brief Class to build various HTTP/2 frames.
 *
 * The `Http2FrameBuilder` class provides methods to build HTTP/2 frames,
 * including data frames, header frames, and control frames (such as GOAWAY and
 * SETTINGS frames). This class allows for the construction of frames with
 * specified flags, stream IDs, and payloads.
 */
class Http2FrameBuilder {
 public:
  /**
   * @brief Builds a generic HTTP/2 frame.
   *
   * This method builds a generic HTTP/2 frame based on the provided parameters.
   * It can be used for various types of frames, including data, header, and
   * control frames.
   *
   * @param type The type of the HTTP/2 frame (e.g., DATA, HEADERS).
   * @param frame_flags The flags for the frame (optional, default is 0).
   * @param stream_id The stream ID associated with the frame (optional, default
   * is 0).
   * @param error_code An error code for certain frames (optional, default is
   * 0).
   * @param increment The increment value for WINDOW_UPDATE frames (optional,
   * default is 0).
   * @param encoded_headers The encoded headers for a HEADERS frame (optional,
   * default is empty).
   * @param data The payload data for the frame (optional, default is empty).
   * @return A vector of bytes representing the built HTTP/2 frame.
   */
  std::vector<uint8_t> BuildFrame(
      Frame type, uint8_t frame_flags = 0, uint32_t stream_id = 0,
      uint32_t error_code = 0, uint32_t increment = 0,
      const std::vector<uint8_t> &encoded_headers = {},
      const std::string &data = "");

  /**
   * @brief Builds a DATA frame.
   *
   * This method builds a HTTP/2 DATA frame with the provided payload data and
   * stream ID.
   *
   * @param data The payload data for the DATA frame.
   * @param stream_id The stream ID associated with the DATA frame (optional,
   * default is 0).
   * @return A vector of bytes representing the built DATA frame.
   */
  std::vector<uint8_t> BuildDataFrame(const std::string &data,
                                      uint32_t stream_id = 0);

  /**
   * @brief Builds a DATA frame from the given byte buffer.
   *
   * This method builds a DATA frame using the provided byte buffer and stream
   * ID.
   *
   * @param bytes A vector of bytes to be included in the DATA frame payload.
   * @param payload_size The size of the payload in the DATA frame.
   * @param stream_id The stream ID associated with the DATA frame.
   * @param frame_flags The flags to apply to the DATA frame.
   * @return A vector of bytes representing the built DATA frame.
   */
  std::vector<uint8_t> BuildDataFrame(std::vector<uint8_t> &bytes,
                                      uint32_t payload_size, uint32_t stream_id,
                                      uint8_t frame_flags);

  /**
   * @brief Builds a DATA frame from a file.
   *
   * This method builds a DATA frame from a file, reading data from the file
   * descriptor.
   *
   * @param fd The file descriptor to read data from.
   * @param file_size The total size of the file to be sent as a DATA frame.
   * @param stream_id The stream ID associated with the DATA frame.
   * @return A vector of bytes representing the built DATA frame.
   */
  std::vector<uint8_t> BuildDataFrameFromFile(int fd, uint64_t file_size,
                                              uint32_t stream_id);

  /**
   * @brief Builds multiple DATA frames from a file.
   *
   * This method builds multiple DATA frames from a file, chunking the data
   * based on the file size.
   *
   * @param fd The file descriptor to read data from.
   * @param file_size The total size of the file to be split into multiple DATA
   * frames.
   * @param stream_id The stream ID associated with the DATA frames.
   * @return A vector of vectors of bytes, each representing a built DATA frame.
   */
  std::vector<std::vector<uint8_t>> BuildDataFramesFromFile(int fd,
                                                            uint64_t file_size,
                                                            uint32_t stream_id);

  /**
   * @brief Builds a HEADER frame.
   *
   * This method builds an HTTP/2 HEADER frame with the provided encoded headers
   * and stream ID.
   *
   * @param encoded_headers The encoded headers to be included in the HEADER
   * frame.
   * @param stream_id The stream ID associated with the HEADER frame.
   * @return A vector of bytes representing the built HEADER frame.
   */
  std::vector<uint8_t> BuildHeaderFrame(
      const std::vector<uint8_t> &encoded_headers, uint32_t stream_id);

  /**
   * @brief Builds a GOAWAY frame.
   *
   * This method builds an HTTP/2 GOAWAY frame with the specified stream ID and
   * error code.
   *
   * @param stream_id The stream ID to associate with the GOAWAY frame.
   * @param error_code The error code to be sent with the GOAWAY frame.
   * @return A vector of bytes representing the built GOAWAY frame.
   */
  std::vector<uint8_t> BuildGoAwayFrame(uint32_t stream_id,
                                        uint32_t error_code);

  /**
   * @brief Builds a SETTINGS frame.
   *
   * This method builds an HTTP/2 SETTINGS frame with the provided frame flags.
   *
   * @param frame_flags The flags to apply to the SETTINGS frame.
   * @return A vector of bytes representing the built SETTINGS frame.
   */
  std::vector<uint8_t> BuildSettingsFrame(uint8_t frame_flags);

  /**
   * @brief Builds a RST_STREAM frame.
   *
   * This method builds an HTTP/2 RST_STREAM frame with the specified stream ID
   * and error code.
   *
   * @param stream_id The stream ID to associate with the RST_STREAM frame.
   * @param error_code The error code to be sent with the RST_STREAM frame.
   * @return A vector of bytes representing the built RST_STREAM frame.
   */
  std::vector<uint8_t> BuildRstStreamFrame(uint32_t stream_id,
                                           uint32_t error_code);

  /**
   * @brief Builds a WINDOW_UPDATE frame.
   *
   * This method builds an HTTP/2 WINDOW_UPDATE frame with the specified stream
   * ID and increment value.
   *
   * @param stream_id The stream ID to associate with the WINDOW_UPDATE frame.
   * @param increment The increment value to apply to the WINDOW_UPDATE frame.
   * @return A vector of bytes representing the built WINDOW_UPDATE frame.
   */
  std::vector<uint8_t> BuildWindowUpdateFrame(uint32_t stream_id,
                                              uint32_t increment);
};

#endif  // INCLUDE_HTTP2_FRAME_BUILDER_H_
