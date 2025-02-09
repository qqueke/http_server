#include "router.hpp"

#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <utility>

#include "log.hpp"
#include "msquic.h"
#include "server.hpp"
#include "utils.hpp"

// Default initializer adds default routes
Router::Router() { AddRoute("BR", "", handleBadRequest); };
Router::~Router() { std::cout << "Deconstructed router\n"; }

void Router::AddRoute(const std::string &method, const std::string &path,
                      const ROUTE_HANDLER &handler) {
  routes[{method, path}] = handler;
}

STATUS_CODE Router::RouteRequest(const std::string &method,
                                 const std::string &path,
                                 const std::string &data, Protocol protocol,
                                 void *context) {
  std::string cacheKey = method + " " + path;

  std::pair<std::string, std::string> routeKey = std::make_pair(method, path);

  if (routes.find(routeKey) != routes.end()) {
    return routes[routeKey](data, protocol, context, cacheKey);
  }

  std::cout << "Error: Undefined route\n";
  return handleBadRequest(data, protocol, context, cacheKey);
}

STATUS_CODE Router::handleBadRequest(const std::string &data, Protocol protocol,
                                     void *context,
                                     const std::string &cacheKey) {
  switch (protocol) {
  case Protocol::HTTP1: {
    std::string response = "HTTP/1.1 400 Bad Request\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: 20\r\n"
                           "\r\n"
                           "Bad Request";
    SSL *clientSSL = (SSL *)context;
    HTTPServer::SendHTTP1Response(clientSSL, response);
  } break;
    // case Protocol::HTTP2:
    //   return handleHTTP2Request(method, path, static_cast<SSL *>(context));

  case Protocol::HTTP3:

  {
    std::string responseHeaders = ":status: 400\n"
                                  "content-type: text/plain\n"
                                  "content-length: 20\n";

    std::string responseData("Bad Request");
    HQUIC Stream = (HQUIC)context;

    HTTPServer::SendHTTP3Response(Stream, responseHeaders, responseData);
  }

  break;
  default:
    LogError("Unknown Protocol");
    break;
  }

  return "400 Bad Request";
}
