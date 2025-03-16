// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file client.h
 * @brief Defines the HttpClient class that supports both TCP and QUIC protocols
 *        for sending HTTP requests.
 *
 * This file contains the class definition for `HttpClient`, which allows a
 * client to send HTTP requests using either the TCP or QUIC protocol. It also
 * provides functionality for parsing requests from a file and sending them to
 * a server.
 */

#ifndef INCLUDE_CLIENT_H_
#define INCLUDE_CLIENT_H_
#include <memory>
#include <string>
#include <vector>

#include "../include/quic_client.h"
#include "../include/tcp_client.h"

/**
 * @class HttpClient
 * @brief A client that supports both TCP and QUIC protocols for sending HTTP
 * requests.
 *
 * This class allows the client to send HTTP requests using either the TCP or
 * QUIC protocol. It supports parsing requests from a file and sending them to
 * the server.
 */
class HttpClient {
 public:
  std::vector<QuicClient> quic_client_vector_;

  /**
   * @brief Constructs an HttpClient object.
   *
   * This constructor initializes the client and sets up the necessary
   * components for both TCP and QUIC client functionalities.
   *
   * @param argc The number of command line arguments.
   * @param argv The array of command line arguments.
   */
  HttpClient(int argc, char *argv[]);

  /**
   * @brief Destroys the HttpClient object.
   *
   * Cleans up any resources associated with the client, including the QUIC and
   * TCP client instances.
   */
  ~HttpClient();

  /**
   * @brief A vector that stores pairs of HTTP request headers and body.
   *
   * This vector contains the HTTP request headers and body data that will be
   * sent by the client. Each pair consists of a header field and its
   * corresponding value.
   */
  std::vector<std::pair<std::string, std::string>> requests_;

  /**
   * @brief Starts the HttpClient and processes the given arguments.
   *
   * This method handles the parsing of command-line arguments and initiates
   * either the TCP or QUIC client to send the HTTP requests.
   *
   * @param argc The number of command line arguments.
   * @param argv The array of command line arguments.
   */
  void Run(int argc, char *argv[]);

  /**
   * @brief Parses HTTP request data from a file.
   *
   * This method reads an HTTP request file and populates the `requests` vector
   * with the parsed headers and body data.
   *
   * @param file_path The path to the file containing HTTP request data.
   */
  void ParseRequestsFromFile(const std::string &file_path);

 private:
  /** A unique pointer to the QuicClient instance used for QUIC-based requests.
   */
  std::unique_ptr<QuicClient> quic_client_;

  /** A unique pointer to the TcpClient instance used for TCP-based requests. */
  std::unique_ptr<TcpClient> tcp_client_;
};

#endif  // INCLUDE_CLIENT_H_
