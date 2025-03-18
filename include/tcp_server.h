// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file tcp_server.h
 * @brief Defines the TcpServer class for managing TCP server connections,
 *        handling HTTP/1 and HTTP/2 requests, and using SSL/TLS encryption.
 *
 * This file contains the class definition for `TcpServer`, which accepts
 * incoming TCP connections, manages SSL/TLS communication, and processes both
 * HTTP/1 and HTTP/2 requests. It also utilizes a router for request routing
 * and a content handler to serve static content.
 */

#ifndef INCLUDE_TCP_SERVER_H_
#define INCLUDE_TCP_SERVER_H_

#include <netinet/in.h>

#include <memory>

#include "../include/codec.h"
#include "../include/database_handler.h"
#include "../include/http2_frame_builder.h"
#include "../include/router.h"
#include "../include/static_content_handler.h"
#include "../include/tls_manager.h"
#include "../include/transport.h"

/**
 * @class TcpServer
 * @brief A server that handles TCP connections, manages SSL/TLS, and processes
 * HTTP requests.
 *
 * This class is responsible for accepting incoming TCP connections, managing
 * TLS encryption, and handling both HTTP/1 and HTTP/2 requests. It utilizes the
 * provided router and content handler to serve appropriate responses.
 */
class TcpServer {
 public:
  /**
   * @brief Constructs a new TcpServer object.
   *
   * Initializes the server with the provided router and content handler,
   * setting up necessary resources for handling TCP connections and HTTP
   * requests.
   *
   * @param router A shared pointer to a Router instance for routing incoming
   * requests.
   * @param content_handler A shared pointer to a StaticContentHandler to serve
   * static content.
   */
  explicit TcpServer(
      const std::shared_ptr<Router> &router,
      const std::shared_ptr<StaticContentHandler> &content_handler,
      const std::shared_ptr<DatabaseHandler> &db_handler);

  /**
   * @brief Destroys the TcpServer object.
   *
   * Cleans up any resources or handles used by the server, including the socket
   * and TLS manager.
   */
  ~TcpServer();

  /**
   * @brief Starts the TCP server to accept incoming connections.
   *
   * This method enters the server's main loop, accepting incoming client
   * connections, processing requests, and managing the life cycle of each
   * connection.
   */
  void Run();

 private:
  /** A unique pointer to the TlsManager that manages SSL/TLS encryption for the
   * server. */
  std::unique_ptr<TlsManager> tls_manager_;

  /** A shared pointer to the TCP transport layer for handling lower-level
   * networking. */
  std::shared_ptr<TcpTransport> transport_;

  /** A shared pointer to the HTTP/2 frame builder used for building HTTP/2
   * frames. */
  std::shared_ptr<Http2FrameBuilder> frame_builder_;

  /** A shared pointer to the HPACK codec used for HTTP/2 header compression. */
  std::shared_ptr<HpackCodec> codec_;

  /** A weak pointer to the router that handles request routing. */
  std::weak_ptr<Router> router_;

  /** A weak pointer to the static content handler used for serving static
   * files. */
  std::weak_ptr<StaticContentHandler> static_content_handler_;

  /** A weak pointer to the static content handler used for serving static
   * files. */
  std::weak_ptr<DatabaseHandler> database_handler_;

  /** The socket used to listen for incoming connections. */
  int socket_;

  /** The address information used for binding the server socket. */
  struct addrinfo *socket_addr_;

  /**
   * @brief Accepts incoming client connections.
   *
   * This method listens for incoming client connections on the server's socket
   * and accepts them, passing the client socket to be processed further.
   */
  void AcceptConnections();

  /**
   * @brief Handles an HTTP request from a client.
   *
   * This method is responsible for processing the HTTP request from a client,
   * either HTTP/1 or HTTP/2, and sending an appropriate response.
   *
   * @param client_socket The socket connected to the client.
   */
  void HandleRequest(int client_socket);

  /**
   * @brief Handles an HTTP/1 request over SSL/TLS.
   *
   * This method processes an HTTP/1 request from the client, securely
   * communicating over SSL/TLS.
   *
   * @param client_ssl The SSL context used for secure communication with the
   * client.
   */
  void HandleHTTP1Request(SSL *client_ssl);

  /**
   * @brief Handles an HTTP/2 request over SSL/TLS.
   *
   * This method processes an HTTP/2 request from the client, securely
   * communicating over SSL/TLS.
   *
   * @param client_ssl The SSL context used for secure communication with the
   * client.
   */
  void HandleHTTP2Request(SSL *client_ssl);
};

#endif  // INCLUDE_TCP_SERVER_H_
