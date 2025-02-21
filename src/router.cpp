#include "router.hpp"

#include <fcntl.h>
#include <msquic.h>
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
#include "server.hpp"
#include "utils.hpp"

// Default initializer adds default routes
Router::Router() { AddRoute("BR", "", handleBadRequest); };
Router::~Router() = default;

void Router::AddRoute(const std::string &method, const std::string &path,
                      const ROUTE_HANDLER &handler) {
  routes[{method, path}] = handler;
}

STATUS_CODE Router::RouteRequest(const std::string &method,
                                 const std::string &path,
                                 const std::string &data, Protocol protocol,
                                 void *context) {
  std::cout << "Method: " << method << " Path: " << path << " Data: " << data
            << std::endl;

  bool acceptEncoding = false;

  // if (path.starts_with("/static/")) {
  //   std::string filePath = "static" + path.substr(7);
  //   // Check how to proceed in here
  //   staticFileHandler(ssl, filePath, acceptEncoding);
  // }

  // std::cout << "Routing request..." << std::endl;
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
    HTTPBase::SendHTTP1Response(clientSSL, response);
  }

  break;
  case Protocol::HTTP2:

  {
    HTTP2Context *ctx = (HTTP2Context *)context;

    SSL *clientSSL = ctx->ssl;
    uint32_t streamId = ctx->streamId;

    std::unordered_map<std::string, std::string> headersMap;

    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    std::vector<uint8_t> encodedHeaders;

    HTTPBase::HPACK_EncodeHeaders(headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;

    frames.emplace_back(
        HTTPBase::HTTP2_BuildHeaderFrame(encodedHeaders, streamId));

    HTTPBase::SendHTTP2Response(clientSSL, frames);
  }

  break;
  case Protocol::HTTP3:

  {
    std::unordered_map<std::string, std::string> headersMap;
    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    // Transform HTTP1 headers into HTTP3
    // Compress headers with QPACK
    std::vector<uint8_t> encodedHeaders;

    HTTPBase::QPACK_EncodeHeaders(headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;

    frames.emplace_back(HTTPBase::HTTP3_BuildHeaderFrame(encodedHeaders));

    HQUIC Stream = (HQUIC)context;

    HTTPBase::SendHTTP3Response(Stream, frames);
  }

  break;
  default:
    LogError("Unknown Protocol");
    break;
  }
}

// In final version should expect headers and data formatted in HTTP1 style
void Router::SendResponse(std::string &headers, const std::string &body,
                          Protocol protocol, void *context) {
  switch (protocol) {
  case Protocol::HTTP1:

  {
    std::string response = headers + body;
    SSL *clientSSL = (SSL *)context;
    HTTPBase::SendHTTP1Response(clientSSL, response);
  }

  break;
  case Protocol::HTTP2:

  {
    HTTP2Context *ctx = (HTTP2Context *)context;

    SSL *clientSSL = ctx->ssl;
    uint32_t streamId = ctx->streamId;

    std::unordered_map<std::string, std::string> headersMap;

    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    std::vector<uint8_t> encodedHeaders;

    HTTPBase::HPACK_EncodeHeaders(headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;

    frames.emplace_back(
        HTTPBase::HTTP2_BuildHeaderFrame(encodedHeaders, streamId));

    frames.emplace_back(HTTPBase::HTTP2_BuildDataFrame(body, streamId));

    HTTPBase::SendHTTP2Response(clientSSL, frames);
  }

  break;

  case Protocol::HTTP3:

  {
    std::unordered_map<std::string, std::string> headersMap;
    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    std::vector<uint8_t> encodedHeaders;

    HTTPBase::QPACK_EncodeHeaders(headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;

    frames.emplace_back(HTTPBase::HTTP3_BuildHeaderFrame(encodedHeaders));

    frames.emplace_back(HTTPBase::HTTP3_BuildDataFrame(body));

    HQUIC Stream = (HQUIC)context;

    HTTPBase::SendHTTP3Response(Stream, frames);
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
                        "Content-Length: 11\r\n"
                        "Connection: close\r\n"
                        "\r\n";

  std::string body = "Bad Request";

  Router::SendResponse(headers, body, protocol, context);
  return "400 Bad Request";
}
