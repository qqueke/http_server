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

void Router::SendResponse(std::string &headers, Protocol protocol,
                          void *context) {
  switch (protocol) {
  case Protocol::HTTP1:

  {
    std::string response = headers;
    SSL *clientSSL = (SSL *)context;
    HTTPServer::SendHTTP1Response(clientSSL, response);
  }

  break;
    // case Protocol::HTTP2:
    //   return handleHTTP2Request(method, path, static_cast<SSL *>(context));

  case Protocol::HTTP3:

  {
    std::string http3Headers = ResponseHTTP1ToHTTP3Headers(headers);

    // Transform HTTP1 headers into HTTP3
    // Compress headers with QPACK
    std::string compressedHeaders = http3Headers;

    std::vector<std::vector<uint8_t>> frames;

    frames.emplace_back(BuildHeaderFrame(compressedHeaders));

    HQUIC Stream = (HQUIC)context;

    HTTPServer::SendHTTP3Response(Stream, frames);
  }

  break;
  default:
    LogError("Unknown Protocol");
    break;
  }
}

// In final version should expect headers and data formatted in HTTP1 style
void Router::SendResponse(std::string &headers, std::string &body,
                          Protocol protocol, void *context) {
  switch (protocol) {
  case Protocol::HTTP1:

  {
    std::string response = headers + body;
    SSL *clientSSL = (SSL *)context;
    HTTPServer::SendHTTP1Response(clientSSL, response);
  }

  break;
    // case Protocol::HTTP2:
    //   return handleHTTP2Request(method, path, static_cast<SSL *>(context));

  case Protocol::HTTP3:

  {
    std::string http3Headers = ResponseHTTP1ToHTTP3Headers(headers);

    // Transform HTTP1 headers into HTTP3
    // Compress headers with QPACK
    std::string compressedHeaders = http3Headers;

    // std::vector<uint8_t> headerFrame = BuildHeaderFrame(compressedHeaders);

    // Process data into one or more frames.
    // std::vector<std::vector<uint8_t>> dataFrames;

    // Put header frame and data frames in frames response
    std::vector<std::vector<uint8_t>> frames;

    frames.emplace_back(BuildHeaderFrame(compressedHeaders));

    frames.emplace_back(BuildDataFrame(body));
    // for (auto &dataFrame : dataFrames) {
    //   frames.emplace_back(dataFrame);
    // }
    // Build frames

    HQUIC Stream = (HQUIC)context;

    HTTPServer::SendHTTP3Response(Stream, frames);
  }

  break;
  default:
    LogError("Unknown Protocol");
    break;
  }
}

STATUS_CODE Router::handleBadRequest(const std::string &data, Protocol protocol,
                                     void *context,
                                     const std::string &cacheKey) {
  // While routes should receive this arguments, they should be abstracted
  // on how to send information to the client
  // Thus we will implement a Send(responseHeaders, responseData, protocol,
  // context); This way our Send() function will take a look at the protocol,
  // the headers and the data and will send it accordingly. After sending we can
  // store the responseHeaders and responseData in the cache

  std::string headers = "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 20\r\n"
                        "Connection: close\r\n"
                        "\r\n";

  std::string body = "Bad Request";

  Router::SendResponse(headers, body, protocol, context);
  return "400 Bad Request";
}
