// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file quic_client.h
 * @brief Defines the QuicClient class for managing client-side QUIC
 * connections.
 *
 * This file contains the class definition for `QuicClient`, which is
 * responsible for establishing and managing QUIC connections, sending data,
 * managing streams, and working with HTTP/3 frames.
 */

#ifndef INCLUDE_QUIC_CLIENT_H_
#define INCLUDE_QUIC_CLIENT_H_

#include <netinet/in.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/codec.h"
#include "../include/http3_frame_builder.h"
#include "../include/router.h"
#include "../include/transport.h"

/**
 * @class QuicClient
 * @brief This class manages the client-side QUIC connection and interaction
 * with the QUIC transport layer. It handles sending data, managing streams, and
 *        working with HTTP/3 frames.
 */
class QuicClient {
 public:
  /**
   * @brief Constructs a QuicClient instance and initializes internal resources.
   * @param argc Argument count passed to the program.
   * @param argv Argument vector passed to the program.
   * @param requests A vector of pairs, each representing a request with headers
   * and data.
   */
  explicit QuicClient(
      int argc, char *argv[],
      const std::vector<std::pair<std::string, std::string>> &requests);

  /**
   * @brief Destroys the QuicClient instance and releases any resources.
   */
  ~QuicClient();

  /**
   * @brief Runs the client, processing arguments and initiating the QUIC
   * connection.
   * @param argc Argument count passed to the program.
   * @param argv Argument vector passed to the program.
   */
  void Run(int argc, char *argv[]);

  /**
   * @brief Function for sending data over QUIC.
   * @param Connection The QUIC connection handle.
   * @param Context QuicClient instance.
   */
  static void QuicSend(_In_ HQUIC Connection, void *Context);

  // Public member variables

  /**
   * @brief A vector of request pairs where each pair represents a header and
   * data for the request.
   */
  const std::vector<std::pair<std::string, std::string>> requests_;

  /**
   * @brief A weak pointer to the router for routing QUIC frames.
   */
  std::weak_ptr<Router> router_;

  /**
   * @brief A shared pointer to the QUIC transport layer.
   */
  std::shared_ptr<QuicTransport> transport_;

  /**
   * @brief A shared pointer to the HTTP/3 frame builder used for encoding
   * HTTP/3 frames.
   */
  std::shared_ptr<Http3FrameBuilder> frame_builder_;

  /**
   * @brief A shared pointer to the QpackCodec used for encoding/decoding HTTP/3
   * headers.
   */
  std::shared_ptr<QpackCodec> codec_;

 private:
  // Private member variables and constants

  /**
   * @brief The QUIC API/function table returned from MsQuicOpen2.
   *        Contains functions for interacting with the QUIC API.
   */
  static const QUIC_API_TABLE *ms_quic_;

  /**
   * @brief The QUIC handle to the registration object, representing the
   * execution context.
   */
  HQUIC registration_;

  /**
   * @brief The QUIC handle to the configuration object that abstracts the
   * connection settings.
   */
  static HQUIC config_;

  /**
   * @brief The TLS secrets for managing encryption.
   */
  QUIC_TLS_SECRETS secrets_;

  /**
   * @brief The configuration for QUIC registration, specifying the profile.
   */
  static constexpr QUIC_REGISTRATION_CONFIG kRegConfig = {
      "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY};

  /**
   * @brief The QUIC status code, used to report the status of QUIC operations.
   */
  QUIC_STATUS status_;

  /**
   * @brief A map holding buffers for each QUIC stream.
   */
  std::unordered_map<HQUIC, std::vector<uint8_t>> quic_buffer_map_;

  /**
   * @brief Loads the QUIC client configuration from the provided arguments.
   * @param argc Argument count passed to the program.
   * @param argv Argument vector passed to the program.
   * @return Status code indicating success or failure.
   */
  int LoadConfiguration(int argc, char *argv[]);

  /**
   * @brief Callback function for stream events in QUIC.
   * @param Stream The QUIC stream handle.
   * @param Context QuicClient instance context passed to the callback.
   * @param Event The event associated with the stream.
   * @return The status of the callback.
   */
  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
      static StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                            _Inout_ QUIC_STREAM_EVENT *Event);

  /**
   * @brief Callback function for connection events in QUIC.
   * @param Connection The QUIC connection handle.
   * @param Context QuicClient instance passed to the callback.
   * @param Event The event associated with the connection.
   * @return The status of the callback.
   */
  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
      static ConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                                _Inout_ QUIC_CONNECTION_EVENT *Event);
};

#endif  // INCLUDE_QUIC_CLIENT_H_
