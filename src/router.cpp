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
  // std::cout << "Method: " << method << " Path: " << path << " Data: " << data
  //           << std::endl;

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

  // std::cout << "Error: Undefined route\n";
  return handleBadRequest(data, protocol, context, cacheKey);
}

void Router::SendResponse(std::string &headers, Protocol protocol,
                          void *context) {
  static constexpr std::string_view altSvcHeader =
      "Alt-Svc: h3=\":4567\"; ma=86400\r\n";

  switch (protocol) {
  case Protocol::HTTP1:

  {
    size_t headerEnd = headers.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
      headers.insert(headerEnd + 2, altSvcHeader);
    }

    std::string response = headers;
    SSL *clientSSL = (SSL *)context;
    HTTPBase::HTTP1_SendMessage(clientSSL, response);
  }

  break;
  case Protocol::HTTP2:

  {
    HTTP2Context *ctx = (HTTP2Context *)context;

    SSL *clientSSL = ctx->ssl;
    struct lshpack_enc *enc = ctx->enc;
    uint32_t streamId = ctx->streamId;

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> headerFrame(256);

    HTTPBase::HPACK_EncodeHeaderIntoFrame(*enc, headersMap, headerFrame);

    HTTPBase::HTTP2_FillHeaderFrame(headerFrame, streamId);

    HTTPBase::HTTP2_SendFrame(clientSSL, headerFrame);
  }

  break;
  case Protocol::HTTP3:

  {
    HQUIC Stream = (HQUIC)context;

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    std::vector<uint8_t> encodedHeaders;

    uint64_t streamId{};
    uint32_t len = (uint32_t)sizeof(streamId);
    if (QUIC_FAILED(
            MsQuic->GetParam(Stream, QUIC_PARAM_STREAM_ID, &len, &streamId))) {
      LogError("Failed to acquire stream id");
    }

    HTTPBase::QPACK_EncodeHeaders(streamId, headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(1);

    frames.emplace_back(HTTPBase::HTTP3_BuildHeaderFrame(encodedHeaders));

    HTTPBase::HTTP3_SendFrames(Stream, frames);
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
  static constexpr std::string_view altSvcHeader =
      "Alt-Svc: h3=\":4567\"; ma=86400\r\n";

  switch (protocol) {
  case Protocol::HTTP1:

  {
    size_t headerEnd = headers.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
      headers.insert(headerEnd + 2, altSvcHeader);
    }

    std::string response = headers + body;
    SSL *clientSSL = (SSL *)context;
    HTTPBase::HTTP1_SendMessage(clientSSL, response);
  }

  break;
  case Protocol::HTTP2:

  {
    HTTP2Context *ctx = (HTTP2Context *)context;

    SSL *clientSSL = ctx->ssl;
    struct lshpack_enc *enc = ctx->enc;
    uint32_t streamId = ctx->streamId;

    std::unordered_map<std::string, std::string> headersMap;

    headersMap.reserve(2);
    // if (headersMap.bucket_count() < 2) {
    //   headersMap.reserve(2);
    //   headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";
    // }

    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> headerFrame(256);
    // if (headerFrame.size() < 256) {
    //   headerFrame.resize(256);
    // }

    HTTPBase::HPACK_EncodeHeaderIntoFrame(*enc, headersMap, headerFrame);

    std::vector<std::vector<uint8_t>> frames;

    frames.reserve(2);
    // if (frames.capacity() < 65535) {
    //   frames.reserve(2);
    // }

    HTTPBase::HTTP2_FillHeaderFrame(headerFrame, streamId);

    frames.emplace_back(std::move(headerFrame));

    frames.emplace_back(
        std::move(HTTPBase::HTTP2_BuildDataFrame(body, streamId)));

    HTTPBase::HTTP2_SendFrames(clientSSL, frames);
  }

  break;

  case Protocol::HTTP3:

  {
    HQUIC Stream = (HQUIC)context;
    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HTTPBase::RespHeaderToPseudoHeader(headers, headersMap);

    std::vector<uint8_t> encodedHeaders;

    uint64_t streamId{};
    uint32_t len = (uint32_t)sizeof(streamId);
    if (QUIC_FAILED(
            MsQuic->GetParam(Stream, QUIC_PARAM_STREAM_ID, &len, &streamId))) {
      LogError("Failed to acquire stream id");
    }

    HTTPBase::QPACK_EncodeHeaders(streamId, headersMap, encodedHeaders);

    std::vector<std::vector<uint8_t>> frames;
    frames.reserve(2);

    frames.emplace_back(HTTPBase::HTTP3_BuildHeaderFrame(encodedHeaders));

    frames.emplace_back(HTTPBase::HTTP3_BuildDataFrame(body));

    HTTPBase::HTTP3_SendFrames(Stream, frames);
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

  // Anything to do here?
  std::string headers = "HTTP/1.1 200 Bad Request\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 12\r\n"
                        "Connection: close\r\n"
                        "\r\n";

  std::string body = "Bad Request\n";

  Router::SendResponse(headers, body, protocol, context);
  return "400 Bad Request";
}
