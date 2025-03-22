// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file http2_request_handler.h
 * @brief Defines the `IHttp2RequestHandler` interface and `Http2FrameHandler`
 * class for handling HTTP/2 frames and their processing.
 *
 * This file provides the interface and class definition for handling various
 * types of HTTP/2 frames, including Data, Headers, Priority, RstStream,
 * Settings, Ping, GoAway, WindowUpdate, and Continuation frames. The
 * `Http2RequestHandler` class processes incoming frames and provides methods to
 * handle different frame types.
 */

#ifndef INCLUDE_HTTP2_REQUEST_HANDLER_H_
#define INCLUDE_HTTP2_REQUEST_HANDLER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/codec.h"
#include "../include/database_handler.h"
#include "../include/header_parser.h"
#include "../include/http2_frame_builder.h"
#include "../include/router.h"
#include "../include/static_content_handler.h"
#include "../include/transport.h"
#include "../lib/ls-hpack/lshpack.h"

/**
 * @brief Interface for HTTP/2 frame handlers.
 *
 * This interface defines the methods to process different types of HTTP/2
 * frames and handle their corresponding actions.
 */
class IHttp2RequestHandler {
 public:
  virtual ~IHttp2RequestHandler() = default;

  /**
   * @brief Processes an HTTP/2 frame based on its type.
   *
   * This method dispatches the frame to the corresponding handler based on its
   * type.
   *
   * @param context The context for processing the frame.
   * @param frame_type The type of the HTTP/2 frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int ProcessFrame(void *context, uint8_t frame_type,
                           uint32_t frame_stream, uint32_t read_offset,
                           uint32_t payload_size, uint8_t frame_flags,
                           SSL *ssl) = 0;

 private:
  /**
   * @brief Handles a DATA frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandleDataFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a HEADERS frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandleHeadersFrame(void *context, uint32_t frame_stream,
                                 uint32_t read_offset, uint32_t payload_size,
                                 uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a PRIORITY frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandlePriorityFrame(void *context, uint32_t frame_stream,
                                  uint32_t read_offset, uint32_t payload_size,
                                  uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a RST_STREAM frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                                   uint32_t read_offset, uint32_t payload_size,
                                   uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a SETTINGS frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandleSettingsFrame(void *context, uint32_t frame_stream,
                                  uint32_t read_offset, uint32_t payload_size,
                                  uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a PING frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandlePingFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a GOAWAY frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                                uint32_t read_offset, uint32_t payload_size,
                                uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a WINDOW_UPDATE frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                                      uint32_t read_offset,
                                      uint32_t payload_size,
                                      uint8_t frame_flags, SSL *ssl) = 0;

  /**
   * @brief Handles a CONTINUATION frame.
   *
   * @param context The context for processing the frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  virtual int HandleContinuationFrame(void *context, uint32_t frame_stream,
                                      uint32_t read_offset,
                                      uint32_t payload_size,
                                      uint8_t frame_flags, SSL *ssl) = 0;
};

/**
 * @brief Handles the processing of HTTP/2 frames.
 *
 * This class implements the IHttp2RequestHandler interface and processes
 * different types of HTTP/2 frames, including data, headers, and various
 * control frames.
 */
class Http2RequestHandler : IHttp2RequestHandler {
 public:
  /**
   * @brief Constructs an HTTP/2 frame handler for a server.
   *
   * @param read_buf The buffer containing the frame data to process.
   * @param is_server Flag indicating if the handler is for a server or client.
   */
  explicit Http2RequestHandler(const std::vector<uint8_t> &read_buf,
                               bool is_server);

  /**
   * @brief Constructs an HTTP/2 frame handler with transport and other
   * components.
   *
   * @param read_buf The buffer containing the frame data to process.
   * @param transport Shared pointer to the transport layer.
   * @param frame_builder Shared pointer to the frame builder.
   * @param hpack_codec Shared pointer to the HPACK codec.
   * @param router Optional shared pointer to the router for request routing.
   * @param content_handler Optional shared pointer to the static content
   * handler.
   */
  explicit Http2RequestHandler(
      const std::vector<uint8_t> &read_buf,
      const std::shared_ptr<TcpTransport> &transport,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder,
      const std::shared_ptr<HpackCodec> &hpack_codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr,
      const std::shared_ptr<DatabaseHandler> &db_handler = nullptr);

  /**
   * @brief Destructor for cleaning up resources.
   */
  ~Http2RequestHandler();

  /**
   * @brief Processes an HTTP/2 frame based on its type.
   *
   * This method is used to process a frame when received, routing it to the
   * appropriate handler.
   *
   * @param context The context for processing the frame.
   * @param frame_type The type of the HTTP/2 frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @return int Status code indicating success or failure.
   */
  int ProcessFrame(void *context, uint8_t frame_type, uint32_t frame_stream,
                   uint32_t read_offset, uint32_t payload_size,
                   uint8_t frame_flags, SSL *ssl) override;

  /**
   * @brief Thread-safe version of ProcessFrame for concurrent processing.
   *
   * @param context The context for processing the frame.
   * @param frame_type The type of the HTTP/2 frame.
   * @param frame_stream The stream ID of the frame.
   * @param read_offset The offset to start reading the frame data.
   * @param payload_size The size of the payload data.
   * @param frame_flags The flags associated with the frame.
   * @param ssl SSL context associated with the frame processing.
   * @param mut Mutex to ensure thread-safety.
   * @return int Status code indicating success or failure.
   */
  int ProcessFrame_TS(void *context, uint8_t frame_type, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut);

 private:
  /**
   * @brief Initializes shared resources for handling frames.
   *
   * @param transport Shared pointer to the transport layer.
   * @param frame_builder Shared pointer to the frame builder.
   * @param hpack_codec Shared pointer to the HPACK codec.
   * @param router Optional shared pointer to the router.
   * @param content_handler Optional shared pointer to the content handler.
   */
  void InitializeSharedResources(
      const std::shared_ptr<TcpTransport> &transport,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder,
      const std::shared_ptr<HpackCodec> &hpack_codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr,
      const std::shared_ptr<DatabaseHandler> &db_handler = nullptr);

  // Static members for shared resources.
  static bool static_init_;
  static std::weak_ptr<Router> router_;
  static std::weak_ptr<StaticContentHandler> static_content_handler_;
  static std::weak_ptr<DatabaseHandler> database_handler_;
  static std::weak_ptr<TcpTransport> transport_;
  static std::weak_ptr<Http2FrameBuilder> frame_builder_;
  static std::weak_ptr<HpackCodec> codec_;
  static HeaderParser header_parser_;
  static std::shared_ptr<Logger> logger_;

  // Instance variables for managing frame data and state.
  const std::vector<uint8_t> &read_buf;
  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      tcp_decoded_headers_map_;
  std::unordered_map<uint32_t, std::vector<uint8_t>> encoded_headers_buf_map_;
  std::unordered_map<uint32_t, std::string> tcp_data_map_;
  struct lshpack_enc enc_;
  struct lshpack_dec dec_;
  uint32_t conn_win_size_;
  std::unordered_map<uint32_t, uint32_t> strm_win_size_map_;
  bool wait_for_cont_frame_;
  bool is_server_;

  /**
   * @brief Encodes headers into a byte array using the HPACK codec.
   *
   * @param headers_map The headers map to encode.
   * @return std::vector<uint8_t> The encoded headers.
   */
  std::vector<uint8_t> EncodeHeaders(
      const std::unordered_map<std::string, std::string> &headers_map);

  /**
   * @brief Handles a router request and forwards it to the appropriate handler.
   *
   * @param frame_stream The stream ID of the frame.
   * @param ssl SSL context for secure processing.
   * @param frame_builder_ptr Shared pointer to the frame builder.
   * @param transport_ptr Shared pointer to the transport layer.
   * @param method The HTTP method used in the request.
   * @param path The requested path.
   * @param data The request data.
   * @return int Status code indicating success or failure.
   */
  int HandleRouterRequest(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path, const std::string &data);

  /**
   * @brief Handles static content requests.
   *
   * This method processes static content requests, such as serving files or
   * other resources.
   *
   * @param frame_stream The stream ID of the frame.
   * @param ssl SSL context for secure processing.
   * @param frame_builder_ptr Shared pointer to the frame builder.
   * @param transport_ptr Shared pointer to the transport layer.
   * @param method The HTTP method used in the request.
   * @param path The requested path.
   * @return int Status code indicating success or failure.
   */
  int HandleStaticContent(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path);

  /**
   * @brief Thread-safe version of HandleStaticContent for concurrent access.
   *
   * @param frame_stream The stream ID of the frame.
   * @param ssl SSL context for secure processing.
   * @param frame_builder_ptr Shared pointer to the frame builder.
   * @param transport_ptr Shared pointer to the transport layer.
   * @param method The HTTP method used in the request.
   * @param path The requested path.
   * @param mut Mutex for thread-safety.
   * @return int Status code indicating success or failure.
   */
  int HandleStaticContent(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path, std::mutex &mut);

  /**
   * @brief Handles a database request and forwards it to the appropriate
   * handler.
   *
   * @param frame_stream The stream ID of the frame.
   * @param ssl SSL context for secure processing.
   * @param frame_builder_ptr Shared pointer to the frame builder.
   * @param transport_ptr Shared pointer to the transport layer.
   * @param method The HTTP method used in the request.
   * @param path The requested path.
   * @param data The request data.
   * @return int Status code indicating success or failure.
   */
  int HandleDatabaseRequest(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path, const std::string &data);

  /**
   * @brief Thread-safe version of HandleRouterRequest.
   *
   * @param frame_stream The stream ID of the frame.
   * @param ssl SSL context for secure processing.
   * @param frame_builder_ptr Shared pointer to the frame builder.
   * @param transport_ptr Shared pointer to the transport layer.
   * @param method The HTTP method used in the request.
   * @param path The requested path.
   * @param data The request data.
   * @param mut Mutex for thread-safety.
   * @return int Status code indicating success or failure.
   */
  int HandleRouterRequest(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path, const std::string &data, std::mutex &mut);

  /**
   * @brief Sends a response to the client.
   *
   * @param frame_stream The stream ID of the frame.
   * @param ssl SSL context for secure processing.
   * @param frame_builder_ptr Shared pointer to the frame builder.
   * @param transport_ptr Shared pointer to the transport layer.
   * @return int Status code indicating success or failure.
   */
  int AnswerRequest(uint32_t frame_stream, SSL *ssl,
                    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
                    const std::shared_ptr<TcpTransport> &transport_ptr);

  /**
   * @brief Thread-safe version of AnswerRequest.
   *
   * @param frame_stream The stream ID of the frame.
   * @param ssl SSL context for secure processing.
   * @param frame_builder_ptr Shared pointer to the frame builder.
   * @param transport_ptr Shared pointer to the transport layer.
   * @param mut Mutex for thread-safety.
   * @return int Status code indicating success or failure.
   */
  int AnswerRequest(uint32_t frame_stream, SSL *ssl,
                    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
                    const std::shared_ptr<TcpTransport> &transport_ptr,
                    std::mutex &mut);

  // Frame handlers for different frame types.
  int HandleDataFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl) override;

  int HandleHeadersFrame(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl) override;

  int HandlePriorityFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl) override;

  int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                           uint32_t read_offset, uint32_t payload_size,
                           uint8_t frame_flags, SSL *ssl) override;

  int HandleSettingsFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl) override;

  int HandlePingFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl) override;

  int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                        uint32_t read_offset, uint32_t payload_size,
                        uint8_t frame_flags, SSL *ssl) override;

  int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) override;

  int HandleContinuationFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) override;

  // Thread-safe frame handlers.
  int HandleDataFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleHeadersFrame(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandlePriorityFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                           uint32_t read_offset, uint32_t payload_size,
                           uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleSettingsFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandlePingFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                        uint32_t read_offset, uint32_t payload_size,
                        uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleContinuationFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl, std::mutex &mut);
};

#endif  // INCLUDE_HTTP2_REQUEST_HANDLER_H_
