// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file quic_server.h
 * @brief Defines the QuicServer class for handling QUIC protocol client
 * requests.
 *
 * This file contains the class definition for `QuicServer`, which implements
 * the QUIC protocol for handling incoming connections, managing stream and
 * connection events, and serving static content using the provided static
 * content handler and router.
 */

#ifndef INCLUDE_QUIC_SERVER_H_
#define INCLUDE_QUIC_SERVER_H_
#include <netinet/in.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/codec.h"
#include "../include/database_handler.h"
#include "../include/http3_frame_builder.h"
#include "../include/router.h"
#include "../include/static_content_handler.h"
#include "../include/transport.h"

/**
 * @class QuicServer
 * @brief A server that implements QUIC protocol to handle client requests.
 *
 * This class is responsible for initializing and managing the QUIC server,
 * handling stream and connection events, and serving static content using
 * the provided static content handler and router.
 */
class QuicServer {
 public:
  /**
   * @brief Construct a new QuicServer object.
   *
   * This constructor initializes the QUIC server with a router, content
   * handler, and command-line arguments. It sets up the necessary
   * configurations for the QUIC server to start accepting connections.
   *
   * @param router A shared pointer to a Router instance used to route the
   * incoming requests.
   * @param content_handler A shared pointer to a StaticContentHandler to handle
   * static content.
   * @param argc The argument count passed from the command line.
   * @param argv The argument values passed from the command line.
   */
  explicit QuicServer(
      const std::shared_ptr<Router> &router,
      const std::shared_ptr<StaticContentHandler> &content_handler,
      const std::shared_ptr<DatabaseHandler> &db_handler, int argc,
      char *argv[]);

  /**
   * @brief Destroy the QuicServer object.
   *
   * This destructor cleans up any resources or handles associated with the QUIC
   * server.
   */
  ~QuicServer();

  /**
   * @brief Parses the stream buffer and extracts data.
   *
   * This method processes the data received in the stream buffer, extracting
   * useful information and decoding it.
   *
   * @param Stream The QUIC stream handle associated with the incoming data.
   * @param strm_buf A reference to a vector of bytes representing the incoming
   * stream data.
   * @param data A reference to a string that will hold the extracted data from
   * the stream buffer.
   */
  void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &strm_buf,
                         std::string &data);

  /**
   * @brief Runs the QUIC server, accepting incoming connections and handling
   * events.
   *
   * This method is responsible for starting the server, accepting new
   * connections, and handling events such as new streams, data events, etc.
   */
  void Run();

  /** A weak pointer to the router used by the server. */
  std::weak_ptr<Router> router_;

  /** A shared pointer to the QUIC transport layer. */
  std::shared_ptr<QuicTransport> transport_;

  /** A shared pointer to the HTTP/3 frame builder. */
  std::shared_ptr<Http3FrameBuilder> frame_builder_;

  /** A shared pointer to the Qpack codec used for HTTP/3 compression. */
  std::shared_ptr<QpackCodec> codec_;

  /** A weak pointer to the static content handler used to serve static files.
   */
  std::weak_ptr<StaticContentHandler> static_content_handler_;

  /** A weak pointer to the static content handler used for serving static
   * files. */
  std::weak_ptr<DatabaseHandler> database_handler_;

 private:
  /** The QUIC API table used for interacting with the MsQuic API. */
  static const QUIC_API_TABLE *ms_quic_;

  /** The QUIC handle for the server registration object. */
  HQUIC registration_;

  /** The QUIC handle for the configuration object. */
  static HQUIC config_;

  /** The registration configuration for low-latency execution profile. */
  static constexpr QUIC_REGISTRATION_CONFIG kRegConfig = {
      "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY};

  /** The QUIC status of the server. */
  QUIC_STATUS status_;

  /** The QUIC listener handle for accepting incoming connections. */
  HQUIC listener_;

  /** The QUIC address the server listens on. */
  QUIC_ADDR listen_addr_;

  /** A map storing stream buffers associated with QUIC streams. */
  std::unordered_map<HQUIC, std::vector<uint8_t>> quic_buffer_map_;

  std::unordered_map<HQUIC, std::mutex> quic_buffer_map_mutex_;
  /**
   * @brief Loads the server configuration from command-line arguments.
   *
   * This function parses the command-line arguments and sets up the server
   * configuration accordingly.
   *
   * @param argc The argument count passed from the command line.
   * @param argv The argument values passed from the command line.
   * @return An integer indicating the success or failure of loading the
   * configuration.
   */
  int LoadConfiguration(int argc, char *argv[]);

  /**
   * @brief Callback function for handling stream events from MsQuic.
   *
   * This function is called when a QUIC stream event occurs, such as data being
   * received or a stream being closed.
   *
   * @param Stream The QUIC stream handle.
   * @param Context QuicServer instance passed to the callback.
   * @param Event The event details for the stream event.
   * @return A status code indicating the result of handling the event.
   */
  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
      static StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                            _Inout_ QUIC_STREAM_EVENT *Event);

  /**
   * @brief Callback function for handling connection events from MsQuic.
   *
   * This function is called when a QUIC connection event occurs, such as a
   * connection being established or closed.
   *
   * @param Connection The QUIC connection handle.
   * @param Context QuicServer instance passed to the callback.
   * @param Event The event details for the connection event.
   * @return A status code indicating the result of handling the event.
   */
  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
      static ConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                                _Inout_ QUIC_CONNECTION_EVENT *Event);

  /**
   * @brief Callback function for handling listener events from MsQuic.
   *
   * This function is called when a QUIC listener event occurs, such as a new
   * connection being accepted or a listener being closed.
   *
   * @param Listener The QUIC listener handle.
   * @param Context QuicServer instance passed to the callback.
   * @param Event The event details for the listener event.
   * @return A status code indicating the result of handling the event.
   */
  _IRQL_requires_max_(PASSIVE_LEVEL)
      _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
      static ListenerCallback(_In_ HQUIC Listener, _In_opt_ void *Context,
                              _Inout_ QUIC_LISTENER_EVENT *Event);
};

#endif  // INCLUDE_QUIC_SERVER_H_
