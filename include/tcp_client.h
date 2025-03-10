// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file tcp_client.h
 * @brief Defines the TcpClient class for managing TCP connections and sending
 *        HTTP requests with HTTP/1 and HTTP/2 support.
 *
 * This file contains the class definition for `TcpClient`, which is responsible
 * for managing the TCP connection to a server, sending HTTP/1 and HTTP/2
 * requests, and handling secure communication using TLS.
 */
#ifndef INCLUDE_TCP_CLIENT_H_
#define INCLUDE_TCP_CLIENT_H_

#include <netinet/in.h>

#include <memory>
#include <string>
#include <vector>

#include "../include/codec.h"
#include "../include/http2_frame_builder.h"
#include "../include/tls_manager.h"
#include "../include/transport.h"

/**
 * @class TcpClient
 * @brief A client that communicates over TCP with HTTP/1 and HTTP/2 support.
 *
 * This class is responsible for managing the TCP connection to a server,
 * handling HTTP/1 and HTTP/2 requests, and utilizing TLS for secure
 * communication.
 */
class TcpClient {
 public:
  /**
   * @brief Constructs a new TcpClient object.
   *
   * Initializes the client with the given command line arguments and request
   * data. It also sets up necessary resources for handling the TCP connection
   * and making HTTP requests.
   *
   * @param argc The number of command line arguments passed to the client.
   * @param argv The command line arguments passed to the client.
   * @param requests A vector of pairs containing the HTTP request URLs and
   * headers to be sent.
   */
  explicit TcpClient(
      int argc, char *argv[],
      const std::vector<std::pair<std::string, std::string>> &requests);

  /**
   * @brief Destroys the TcpClient object.
   *
   * Cleans up any resources used by the client, such as closing the socket and
   * freeing any allocated memory.
   */
  ~TcpClient();

  /**
   * @brief Starts the TCP client to send HTTP requests to the server.
   *
   * This method sends the specified HTTP/1 and HTTP/2 requests to the server
   * and processes the responses.
   */
  void Run();

 private:
  /** A unique pointer to the TlsManager that manages SSL/TLS encryption for the
   * client. */
  std::unique_ptr<TlsManager> tls_manager_;

  /** A shared pointer to the TCP transport layer for handling lower-level
   * networking. */
  std::shared_ptr<TcpTransport> transport_;

  /** A shared pointer to the HTTP/2 frame builder used for constructing HTTP/2
   * frames. */
  std::shared_ptr<Http2FrameBuilder> frame_builder_;

  /** A shared pointer to the HPACK codec used for HTTP/2 header compression. */
  std::shared_ptr<HpackCodec> codec_;

  /** The socket used for the client to connect to the server. */
  int socket_;

  /** The address information used for connecting the client to the server. */
  struct addrinfo *socket_addr_;

  /** A vector of request data containing HTTP request URLs and associated
   * headers. */
  const std::vector<std::pair<std::string, std::string>> requests_;

  /**
   * @brief Sends an HTTP/1 request to the server.
   *
   * This method sends an HTTP/1 request over a secure SSL/TLS connection.
   *
   * @param client_ssl The SSL context used for secure communication with the
   * server.
   */
  void SendHttp1Request(SSL *client_ssl);

  /**
   * @brief Sends an HTTP/2 request to the server.
   *
   * This method sends an HTTP/2 request over a secure SSL/TLS connection.
   *
   * @param client_ssl The SSL context used for secure communication with the
   * server.
   */
  void SendHttp2Request(SSL *client_ssl);

  /**
   * @brief Receives an HTTP/2 response from the server.
   *
   * This method reads the HTTP/2 response from the server and processes it.
   * It is invoked while ensuring proper synchronization using a mutex.
   *
   * @param client_ssl The SSL context used for secure communication with the
   * server.
   * @param conn_mutex The mutex used to synchronize access to the SSL.
   */
  void RecvHttp2Response(SSL *client_ssl, std::mutex &conn_mutex);
};

#endif  // INCLUDE_TCP_CLIENT_H_
