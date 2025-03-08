#include "server.h"

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
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#include "log.h"
#include "quic_server.h"
#include "router.h"
#include "tcp_server.h"
#include "utils.h"

// #define HTTP2_DEBUG

bool shouldShutdown(false);

static void sendFile(SSL *client_ssl, const std::string &file_path,
                     bool accept_enc) {
  int fileFd = open(file_path.c_str(), O_RDONLY);

  struct stat fileStat{};
  if (fstat(fileFd, &fileStat) == -1) {
    LogError("Error getting file stats");
    close(fileFd);
    return;
  }

  std::string httpResponse = "HTTP/1.1 200 OK\r\n";
  httpResponse +=
      "Content-Length: " + std::to_string(fileStat.st_size) + "\r\n";

  if (accept_enc) {
    httpResponse += "Content-Encoding: gzip\r\n";
  }

  // verifyContentType(file_path, httpResponse);

  // verify  content type
  ssize_t bytesSent =
      SSL_write(client_ssl, httpResponse.data(), (int)httpResponse.size());

  if (bytesSent <= 0) {
    int err = SSL_get_error(client_ssl, (int)bytesSent);
    LogError("SSL_write failed: " + std::to_string(err));
    close(fileFd);
    return;
  }

  if (BIO_get_ktls_send(SSL_get_wbio(client_ssl))) {
    bytesSent = SSL_sendfile(client_ssl, fileFd, 0, fileStat.st_size, 0);
    if (bytesSent >= 0) {
      close(fileFd);
      return;
    }
    LogError("SSL_sendfile failed, falling back to manual send");
  }

  std::array<char, 4096> buffer{};

  while (read(fileFd, buffer.data(), buffer.size()) > 0) {
    bytesSent = SSL_write(client_ssl, buffer.data(), buffer.size());

    if (bytesSent <= 0) {
      int err = SSL_get_error(client_ssl, (int)bytesSent);
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

void HttpServer::ValidateHeaders(const std::string &request,
                                 std::string &method, std::string &path,
                                 std::string &body, bool &accept_enc) {
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
    accept_enc = true;
  }

  // If all validations pass
  std::cout << "Request successfully validated!\n";
}

void HttpServer::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &headers_map) {
  static constexpr std::array<std::string_view, 3> requiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : requiredHeaders) {
    if (headers_map.find(std::string(header)) == headers_map.end()) {
      // LogError("Failed to validate pseudo-headers (missing header field)");
      headers_map[":method"] = "BR";
      headers_map[":path"] = "";
      return;
    }
  }
}

HttpServer::~HttpServer() {
  std::cout << "Server shutdown gracefully" << std::endl;
}

void HttpServer::AddRoute(const std::string &method, const std::string &path,
                          const ROUTE_HANDLER &handler) {
  router_->AddRoute(method, path, handler);
}

void HttpServer::Run() {
  quic_server_->Run();
  tcp_server_->Run();
}

void HttpServer::PrintFromServer() { std::cout << "Hello from server\n"; }

HttpServer::HttpServer(int argc, char *argv[]) {
  router_ = std::make_shared<Router>();
  tcp_server_ = std::make_unique<TcpServer>(router_);
  quic_server_ = std::make_unique<QuicServer>(router_, argc, argv);
};
