// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file http3_request_handler.h
 * @brief Defines the `IHttp3FrameHandler` interface and `Http3FrameHandler`
 * class for handling HTTP/3 frames and their processing.
 *
 * This file provides the interface and class definition for handling various
 * types of HTTP/3 frames, including Data, Headers, Priority, RstStream,
 * Settings, Ping, GoAway, WindowUpdate, and Continuation frames. The
 * `Http2RequestHandler` class processes incoming frames and provides methods to
 * handle different frame types.
 */

#ifndef INCLUDE_HTTP3_REQUEST_HANDLER_H_
#define INCLUDE_HTTP3_REQUEST_HANDLER_H_
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/codec.h"
#include "../include/database_handler.h"
#include "../include/header_parser.h"
#include "../include/http3_frame_builder.h"
#include "../include/router.h"
#include "../include/static_content_handler.h"
#include "../include/transport.h"

/**
 * @class Http3FrameHandler
 * @brief Handles HTTP/3 frame processing, including encoding, decoding, and
 * managing static content, routing, and frame building.
 *
 * The `Http3FrameHandler` class processes HTTP/3 frames and interacts with QUIC
 * transport, HTTP/3 frame building, header encoding/decoding, routing, and
 * static content handling. This class is designed to handle the HTTP/3 frame
 * lifecycle, including processing different frame types (e.g., headers, data,
 * settings, etc.) and managing QUIC stream interactions.
 */
class Http3RequestHandler {
 public:
  /**
   * @brief Constructs a new Http3FrameHandler instance.
   *
   * Initializes shared resources for handling HTTP/3 frames, QUIC transport,
   * frame building, and header encoding/decoding.
   *
   * @param transport A shared pointer to the QUIC transport layer.
   * @param http3_frame_builder A shared pointer to the HTTP/3 frame builder.
   * @param codec A shared pointer to the Qpack codec for header
   * compression/decompression.
   * @param router A shared pointer to the router (optional).
   * @param content_handler A shared pointer to the static content handler
   * (optional).
   */
  explicit Http3RequestHandler(
      const std::shared_ptr<QuicTransport> &transport,
      const std::shared_ptr<Http3FrameBuilder> &http3_frame_builder,
      const std::shared_ptr<QpackCodec> &codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr,
      const std::shared_ptr<DatabaseHandler> &db_handler = nullptr);

  /**
   * @brief Destructor for Http3FrameHandler.
   */
  ~Http3RequestHandler();

  /**
   * @brief Processes the frames for a given QUIC stream.
   *
   * Iterates through the provided stream buffer, processes the frames, and
   * performs necessary actions based on the frame types.
   *
   * @param stream A handle to the QUIC stream.
   * @param stream_buffer The buffer containing the data for the frames.
   * @return int A status code indicating the result of the processing.
   */
  int ProcessFrames(HQUIC &stream, std::vector<uint8_t> &stream_buffer);

  /**
   * @brief Processes a single HTTP/3 frame within the provided stream.
   *
   * Decodes the frame, identifies its type, and performs the necessary actions
   * to process the frame.
   *
   * @param stream A handle to the QUIC stream.
   * @param iter An iterator for the buffer containing the frame data.
   * @param frame_type The type of the frame.
   * @param payload_size The size of the frame payload.
   * @param headers_map A map of headers associated with the frame.
   * @param data The data associated with the frame.
   * @return int A status code indicating the result of the frame processing.
   */
  int ProcessFrame(HQUIC &stream, std::vector<uint8_t>::iterator &iter,
                   uint64_t frame_type, uint64_t payload_size,
                   std::unordered_map<std::string, std::string> &headers_map,
                   std::string &data);

 private:
  /**
   * @brief Initializes shared resources for the handler.
   *
   * Initializes shared resources such as the QUIC transport, frame builder,
   * codec, and others that are used for processing HTTP/3 frames.
   *
   * @param transport A shared pointer to the QUIC transport layer.
   * @param frame_builder A shared pointer to the HTTP/3 frame builder.
   * @param hpack_codec A shared pointer to the Qpack codec.
   * @param router A shared pointer to the router (optional).
   * @param content_handler A shared pointer to the static content handler
   * (optional).
   */
  void InitializeSharedResources(
      const std::shared_ptr<QuicTransport> &transport,
      const std::shared_ptr<Http3FrameBuilder> &frame_builder,
      const std::shared_ptr<QpackCodec> &hpack_codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr,
      const std::shared_ptr<DatabaseHandler> &db_handler = nullptr);

  /** A flag indicating whether static resources have been initialized. */
  static bool static_init_;

  /** A weak pointer to the router used for routing HTTP/3 requests. */
  static std::weak_ptr<Router> router_;

  /** A weak pointer to the QUIC transport layer. */
  static std::weak_ptr<QuicTransport> transport_;

  /** A weak pointer to the HTTP/3 frame builder. */
  static std::weak_ptr<Http3FrameBuilder> frame_builder_;

  /** A weak pointer to the Qpack codec used for header compression. */
  static std::weak_ptr<QpackCodec> codec_;

  /** A weak pointer to the static content handler. */
  static std::weak_ptr<StaticContentHandler> static_content_handler_;

  /** A weak pointer to the static content handler used for serving static
   * files. */
  std::weak_ptr<DatabaseHandler> database_handler_;

  /** A header parser used to parse HTTP/3 headers. */
  static HeaderParser header_parser_;

  /** A flag indicating whether the handler is running on the server. */
  bool is_server_;

  /**
   * @brief Encodes the given headers into the required format for HTTP/3
   * frames.
   *
   * @param headers_map A map of headers to be encoded.
   * @return std::vector<uint8_t> The encoded headers.
   */
  std::vector<uint8_t> EncodeHeaders(
      const std::unordered_map<std::string, std::string> &headers_map);

  /**
   * @brief Handles static content requests and sends appropriate responses.
   *
   * This function serves static content (e.g., files) based on the request.
   *
   * @param stream A handle to the QUIC stream.
   * @param headers_map A map of headers associated with the request.
   * @param data The request data.
   * @param frame_builder_ptr A shared pointer to the frame builder.
   * @param transport_ptr A shared pointer to the QUIC transport layer.
   * @return int A status code indicating the result of handling the static
   * content.
   */
  int HandleStaticContent(
      HQUIC &stream, std::unordered_map<std::string, std::string> &headers_map,
      std::string &data,
      const std::shared_ptr<Http3FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<QuicTransport> &transport_ptr);

  /**
   * @brief Handles HTTP/3 router requests.
   *
   * Routes HTTP/3 requests to the appropriate handler based on the request
   * method and path.
   *
   * @param stream A handle to the QUIC stream.
   * @param frame_builder_ptr A shared pointer to the frame builder.
   * @param transport_ptr A shared pointer to the QUIC transport layer.
   * @param method The HTTP method (e.g., GET, POST).
   * @param path The requested URL path.
   * @param data The request data.
   * @return int A status code indicating the result of routing the request.
   */
  int HandleRouterRequest(
      HQUIC &stream,
      const std::shared_ptr<Http3FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<QuicTransport> &transport_ptr, std::string &method,
      std::string &path, const std::string &data);

  /**
   * @brief Sends a response to a HTTP/3 request.
   *
   * Sends an appropriate response based on the request headers and data.
   *
   * @param stream A handle to the QUIC stream.
   * @param headers_map A map of headers associated with the request.
   * @param data The request data.
   * @return int A status code indicating the result of sending the response.
   */
  int AnswerRequest(HQUIC &stream,
                    std::unordered_map<std::string, std::string> &headers_map,
                    std::string &data);

  /**
   * @brief Handles a Data frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the Data frame.
   */
  int HandleDataFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a Headers frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the Headers
   * frame.
   */
  int HandleHeadersFrame(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a Priority frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the Priority
   * frame.
   */
  int HandlePriorityFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a RstStream frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the RstStream
   * frame.
   */
  int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                           uint32_t read_offset, uint32_t payload_size,
                           uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a Settings frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the Settings
   * frame.
   */
  int HandleSettingsFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a Ping frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the Ping frame.
   */
  int HandlePingFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a GoAway frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the GoAway
   * frame.
   */
  int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                        uint32_t read_offset, uint32_t payload_size,
                        uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a WindowUpdate frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the
   * WindowUpdate frame.
   */
  int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl);

  /**
   * @brief Handles a Continuation frame in an HTTP/3 stream.
   *
   * @param context The context associated with the frame.
   * @param frame_stream The stream ID associated with the frame.
   * @param read_offset The read offset.
   * @param payload_size The size of the payload.
   * @param frame_flags Flags associated with the frame.
   * @param ssl A pointer to the SSL structure (if applicable).
   * @return int A status code indicating the result of handling the
   * Continuation frame.
   */
  int HandleContinuationFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl);
};

#endif  // INCLUDE_HTTP3_REQUEST_HANDLER_H_
