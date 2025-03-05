#include "server.hpp"

#include <fcntl.h>
#include <lshpack.h>
#include <msquic.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/poll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "common.hpp"
#include "framehandler.hpp"
#include "log.hpp"
#include "quicserver.hpp"
#include "router.hpp"
#include "tcpserver.hpp"
#include "tlsmanager.hpp"
#include "utils.hpp"

// #define HTTP2_DEBUG

bool shouldShutdown(false);

// std::string Router::StaticFileHandler(const std::string &filePath,
//                                       bool acceptEncoding, Protocol protocol,
//                                       void *context) {
//   std::string headers = "HTTP/1.1 200 OK\r\n";
//
//   uint64_t fileSize = 0;
//   if (acceptEncoding) {
//     struct stat buf{};
//     int error = stat((filePath + ".gz").c_str(), &buf);
//     // File exists
//     if (error == 0) {
//       fileSize = buf.st_size;
//     } else {
//       fileSize = CompressFile(filePath, filePath + ".gz", GZIP);
//     }
//   }
//
//   if (fileSize != 0) {
//     headers += "Content-Encoding: gzip\r\n";
//     headers += "Content-Length: " + std::to_string(fileSize) + "\r\n\r\n";
//   }
//
//   static constexpr std::string_view altSvcHeader =
//       "Alt-Svc: h3=\":4567\"; ma=86400\r\n";
//
//   switch (protocol) {
//   case Protocol::HTTP1:
//
//   {
//     size_t headerEnd = headers.find("\r\n\r\n");
//     if (headerEnd != std::string::npos) {
//       headers.insert(headerEnd + 2, altSvcHeader);
//     }
//
//     std::string response = headers + body;
//     SSL *clientSSL = (SSL *)context;
//
//     sendFile(clientSSL, filePath, acceptEncoding);
//     HttpCore::HTTP1_SendMessage(clientSSL, response);
//   }
//
//   break;
//   case Protocol::HTTP2:
//
//   {
//     HTTP2Context *ctx = (HTTP2Context *)context;
//
//     SSL *clientSSL = ctx->ssl;
//     struct lshpack_enc *enc = ctx->enc;
//     uint32_t streamId = ctx->streamId;
//
//     std::unordered_map<std::string, std::string> headersMap;
//
//     headersMap.reserve(2);
//
//     HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
//
//     headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";
//
//     std::vector<uint8_t> headerFrame(256);
//
//     HttpCore::HPACK_EncodeHeaderIntoFrame(*enc, headersMap, headerFrame);
//
//     std::vector<std::vector<uint8_t>> frames;
//
//     frames.reserve(2);
//
//     HttpCore::HTTP2_FillHeaderFrame(headerFrame, streamId);
//
//     frames.emplace_back(std::move(headerFrame));
//
//     frames.emplace_back(
//         std::move(HttpCore::HTTP2_BuildDataFrame(body, streamId)));
//
//     HttpCore::HTTP2_SendFrames(clientSSL, frames);
//   }
//
//   break;
//
//   case Protocol::HTTP3:
//
//   {
//     HQUIC Stream = (HQUIC)context;
//     std::unordered_map<std::string, std::string> headersMap;
//     headersMap.reserve(2);
//
//     HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
//
//     std::vector<uint8_t> encodedHeaders;
//
//     uint64_t streamId{};
//     uint32_t len = (uint32_t)sizeof(streamId);
//     if (QUIC_FAILED(
//             MsQuic->GetParam(Stream, QUIC_PARAM_STREAM_ID, &len, &streamId)))
//             {
//       LogError("Failed to acquire stream id");
//     }
//
//     HttpCore::QPACK_EncodeHeaders(streamId, headersMap, encodedHeaders);
//
//     std::vector<std::vector<uint8_t>> frames;
//     frames.reserve(2);
//
//     frames.emplace_back(HttpCore::HTTP3_BuildHeaderFrame(encodedHeaders));
//
//     frames.emplace_back(HttpCore::HTTP3_BuildDataFrame(body));
//
//     HttpCore::HTTP3_SendFrames(Stream, frames);
//   }
//
//   break;
//   default:
//     LogError("Unknown Protocol");
//     break;
//   }
// }

static void verifyContentType(const std::string &filePath,
                              std::string &httpResponse) {
  std::string fileExtension{};
  for (int pos = (int)filePath.size() - 1; pos >= 0; --pos) {
    if (filePath[pos] == '.') {
      fileExtension = filePath.substr(pos, filePath.size() - pos);
    }
  }

  if (fileExtension == ".html") {
    httpResponse += "Content-Type: text/html\r\n";
  }
  if (fileExtension == ".css") {
    httpResponse += "Content-Type: text/css\r\n";
  }
  if (fileExtension == ".js") {
    httpResponse += "Content-Type: text/javascript\r\n";
  }
  if (fileExtension == ".json") {
    httpResponse += "Content-Type: application/json\r\n";
  }
  if (fileExtension == ".xml") {
    httpResponse += "Content-Type: application/xml\r\n";
  }
  if (fileExtension == ".txt") {
    httpResponse += "Content-Type: text/plain\r\n";
  }
  if (fileExtension == ".jpg") {
    httpResponse += "Content-Type: image/jpeg\r\n";
  }
  if (fileExtension == ".jpeg") {
    httpResponse += "Content-Type: image/jpeg\r\n";
  }
  if (fileExtension == ".png") {
    httpResponse += "Content-Type: image/png\r\n";
  }
  if (fileExtension == ".gif") {
    httpResponse += "Content-Type: image/gif\r\n";
  }
  if (fileExtension == ".svg") {
    httpResponse += "Content-Type: text/svg\r\n";
  }
  if (fileExtension == ".webp") {
    httpResponse += "Content-Type: image/webp\r\n";
  }
  if (fileExtension == ".mp3") {
    httpResponse += "Content-Type: audio/mpeg\r\n";
  }
  if (fileExtension == ".wav") {
    httpResponse += "Content-Type: audio/wav\r\n";
  }
  if (fileExtension == ".mp4") {
    httpResponse += "Content-Type: video/mp4\r\n";
  }
  if (fileExtension == ".webm") {
    httpResponse += "Content-Type: video/webm\r\n";
  }
  if (fileExtension == ".woff") {
    httpResponse += "Content-Type: font/woff\r\n";
  }
  if (fileExtension == ".woff2") {
    httpResponse += "Content-Type: font/woff2\r\n";
  }
  if (fileExtension == ".ttf") {
    httpResponse += "Content-Type: font/ttf\r\n";
  }
  if (fileExtension == ".otf") {
    httpResponse += "Content-Type: font/otf\r\n";
  }
  if (fileExtension == ".pdf") {
    httpResponse += "Content-Type: application/pdf\r\n";
  }
  if (fileExtension == ".zip") {
    httpResponse += "Content-Type: application/zip\r\n";
  }
  if (fileExtension == ".gz") {
    httpResponse += "Content-Type: application/gzip\r\n";
  }

  httpResponse += "\r\n";
}

static void sendFile(SSL *clientSSL, const std::string &filePath,
                     bool acceptEncoding) {
  int fileFd = open(filePath.c_str(), O_RDONLY);

  struct stat fileStat{};
  if (fstat(fileFd, &fileStat) == -1) {
    LogError("Error getting file stats");
    close(fileFd);
    return;
  }

  std::string httpResponse = "HTTP/1.1 200 OK\r\n";
  httpResponse +=
      "Content-Length: " + std::to_string(fileStat.st_size) + "\r\n";

  if (acceptEncoding) {
    httpResponse += "Content-Encoding: gzip\r\n";
  }

  verifyContentType(filePath, httpResponse);

  // verify  content type
  ssize_t bytesSent =
      SSL_write(clientSSL, httpResponse.data(), (int)httpResponse.size());

  if (bytesSent <= 0) {
    int err = SSL_get_error(clientSSL, (int)bytesSent);
    LogError("SSL_write failed: " + std::to_string(err));
    close(fileFd);
    return;
  }

  if (BIO_get_ktls_send(SSL_get_wbio(clientSSL))) {
    bytesSent = SSL_sendfile(clientSSL, fileFd, 0, fileStat.st_size, 0);
    if (bytesSent >= 0) {
      close(fileFd);
      return;
    }
    LogError("SSL_sendfile failed, falling back to manual send");
  }

  std::array<char, 4096> buffer{};

  while (read(fileFd, buffer.data(), buffer.size()) > 0) {
    bytesSent = SSL_write(clientSSL, buffer.data(), buffer.size());

    if (bytesSent <= 0) {
      int err = SSL_get_error(clientSSL, (int)bytesSent);
      LogError("SSL_write failed: " + std::to_string(err));
      close(fileFd);
      return;
    }
  }

  close(fileFd);
}

std::string HttpServer::threadSafeStrerror(int errnum) {
  std::lock_guard<std::mutex> lock(strerrorMutex);
  return {strerror(errnum)};
}

// void HttpServer::staticFileHandler(SSL *clientSSL, const std::string
// &filePath,
//                                    bool acceptEncoding) {
//   if (acceptEncoding) {
//     // find if a precomputed compressed file exists and send it
//     struct stat buf{};
//     int err = stat((filePath + ".gz").c_str(), &buf);
//     // file exists
//     if (err == 0) {
//       sendFile(clientSSL, filePath + ".gz", acceptEncoding);
//       return;
//     }
//
//     // otherwise compress it on the fly and send It
//     if (CompressFile(filePath, filePath + ".gz", GZIP)) {
//       sendFile(clientSSL, filePath + ".gz", acceptEncoding);
//       return;
//     }
//
//     LogError("Compression failed, falling back to full file");
//   }
//
//   sendFile(clientSSL, filePath, acceptEncoding);
// }

void HttpServer::ValidateHeaders(const std::string &request,
                                 std::string &method, std::string &path,
                                 std::string &body, bool &acceptEncoding) {
  std::istringstream requestStream(request);
  std::string line;

  std::getline(requestStream, line);
  std::istringstream requestLine(line);
  std::string protocol;
  requestLine >> method >> path >> protocol;

  if (method != "GET" && method != "POST" && method != "PUT") {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  if (path.empty() || path[0] != '/' || path.find("../") != std::string::npos) {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  if (protocol != "HTTP/1.1" && protocol != "HTTP/2") {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  // header, value
  std::unordered_map<std::string, std::string> headers;
  while (std::getline(requestStream, line) && !line.empty()) {
    if (line.size() == 1) {
      continue;
    }

    auto colonPos = line.find(": ");
    if (colonPos == std::string::npos) {
      LogError("Request validation was unsuccessful");
      method = "BR";
      return;
    }

    std::string key = line.substr(0, colonPos);
    std::string value = line.substr(colonPos + 2);

    headers[key] = value;
  }

  // Validate Headers

  // If we don't  find  host then it is a bad request
  if (headers.find("Host") == headers.end()) {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  // If is a POST and has  no content length it is a bad request
  if (method == "POST" && headers.find("Content-Length") == headers.end()) {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  // Parse Body (if has content-length)
  if (headers.find("Content-Length") != headers.end()) {
    size_t contentLength = std::stoi(headers["Content-Length"]);

    body.resize(contentLength);
    requestStream.read(body.data(), (long)contentLength);

    // If body size  doesnt match the content length defined then bad request
    if (body.size() != contentLength) {
      LogError("Request validation was unsuccessful");
      method = "BR";
      return;
    }
  }

  // Not even bothering with enconding type
  if (headers.find("Accept-Encoding") != headers.end()) {
    acceptEncoding = true;
  }

  // If all validations pass
  std::cout << "Request successfully validated!\n";
}

void HttpServer::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &headersMap) {
  static constexpr std::array<std::string_view, 3> requiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : requiredHeaders) {
    if (headersMap.find(std::string(header)) == headersMap.end()) {
      // LogError("Failed to validate pseudo-headers (missing header field)");
      headersMap[":method"] = "BR";
      headersMap[":path"] = "";
      return;
    }
  }
}

HttpServer::~HttpServer() {
  std::cout << "Server shutdown gracefully" << std::endl;
}

void HttpServer::AddRoute(const std::string &method, const std::string &path,
                          const ROUTE_HANDLER &handler) {
  router->AddRoute(method, path, handler);
}

void HttpServer::Run() {
  quicServer->Run();
  tcpServer->Run();
}

void HttpServer::PrintFromServer() { std::cout << "Hello from server\n"; }

HttpServer::HttpServer(int argc, char *argv[]) {
  router = std::make_shared<Router>();
  tcpServer = std::make_unique<TcpServer>(router);
  quicServer = std::make_unique<QuicServer>(router, argc, argv);
};
