#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>

#include "log.hpp"
#include "server.hpp"

inline std::string helloHandler(SSL *clientSSL, const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 200 OK\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 13\r\n"
                             "\r\n"
                             "Hello, world!\n";
  size_t bytesSent = SSL_write(clientSSL, httpResponse, strlen(httpResponse));

  if (bytesSent <= 0) {
    LogError("Failed to send response");
  }

  HTTPServer::storeInCache(cacheKey, std::string(httpResponse));

  return "200 OK";
}

// Example function handler for GET /goodbye
inline std::string goodbyeHandler(SSL *clientSSL, const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 200 OK\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 15\r\n"
                             "\r\n"
                             "Goodbye, world!\n";
  size_t bytesSent = SSL_write(clientSSL, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {
    LogError("Failed to send response");
  }

  HTTPServer::storeInCache(cacheKey, std::string(httpResponse));

  return "200 OK";
}
