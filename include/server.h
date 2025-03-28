// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file server.h
 * @brief Defines the HttpServer class, which handles both TCP and QUIC
 * protocols with routing support.
 *
 * This file contains the class definition for `HttpServer`, which integrates
 * both TCP and QUIC server functionalities to handle incoming HTTP requests and
 * provides dynamic routing of requests based on HTTP methods and paths.
 */

#ifndef INCLUDE_SERVER_H_
#define INCLUDE_SERVER_H_

#include <msquic.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <memory>
#include <string>

// #include "../include/database.h"
#include "../include/database_handler.h"
#include "../include/quic_server.h"
#include "../include/router.h"
#include "../include/tcp_server.h"

/**
 * @class HttpServer
 * @brief A server that handles both TCP and QUIC protocols with routing
 * support.
 *
 * This class integrates both TCP and QUIC server functionalities to handle
 * incoming HTTP requests. It also supports dynamic routing of requests based on
 * HTTP methods and paths.
 */
class HttpServer {
 public:
  /**
   * @brief Constructs an HttpServer object.
   *
   * This constructor initializes the server by setting up the necessary
   * components such as the TCP and QUIC servers, router, and static content
   * handler.
   *
   * @param argc The number of command line arguments.
   * @param argv The array of command line arguments.
   */
  HttpServer(int argc, char *argv[]);

  /**
   * @brief Destroys the HttpServer object.
   *
   * Cleans up any resources associated with the server, including shutting down
   * the TCP and QUIC servers.
   */
  ~HttpServer();

  /**
   * @brief Adds a new route to the server.
   *
   * This method allows you to define new routes by specifying an HTTP method, a
   * path, and the associated route handler function.
   *
   * @param method The HTTP method (e.g., GET, POST) for the route.
   * @param path The path for the route (e.g., /api/resource).
   * @param handler The handler function that processes requests for this route.
   */
  void AddStringHeaderRoute(const std::string &method, const std::string &path,
                            const ROUTE_HANDLER &handler);

  void AddMapHeaderRoute(const std::string &method, const std::string &path,
                         const OPT_ROUTE_HANDLER &handler);
  /**
   * @brief Starts the HttpServer to handle incoming connections and requests.
   *
   * This method runs both the TCP and QUIC servers, enabling them to accept
   * incoming client connections, handle requests, and serve content based on
   * the routes.
   */
  void Run();

  /** A shared pointer to the Router instance that manages request routing. */
  std::shared_ptr<Router> router_;

 private:
  /** A unique pointer to the TcpServer instance. */
  std::unique_ptr<TcpServer> tcp_server_;

  /** A unique pointer to the QuicServer instance. */
  std::unique_ptr<QuicServer> quic_server_;

  // /** A shared pointer to the Database instance that manages database
  //  * operations. */
  // std::shared_ptr<Database> db_;

  /** A shared pointer to the StaticContentHandler used to serve static content.
   */
  std::shared_ptr<StaticContentHandler> static_content_handler_;

  /** A shared pointer to the DatabaseHandler used to forward queries to the
   * database server
   */
  std::shared_ptr<DatabaseHandler> database_handler_;
};

#endif  // INCLUDE_SERVER_H_
