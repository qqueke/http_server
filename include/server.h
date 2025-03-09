
#ifndef HTTPSERVER_HPP
#define HTTPSERVER_HPP

#include <msquic.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

#include "common.h"
#include "quic_server.h"
#include "router.h"
#include "tcp_server.h"

class HttpServer : public HttpCore {
public:
  HttpServer(int argc, char *argv[]);

  ~HttpServer();

  void AddRoute(const std::string &method, const std::string &path,
                const ROUTE_HANDLER &handler);
  void Run();

  std::unique_ptr<HttpCore> http;

  void staticFileHandler(SSL *client_ssl, const std::string &file_path,
                         bool accept_enc);

  static void storeInCache(const std::string &cacheKey,
                           const std::string &response);

  void PrintFromServer();

  static void ValidateHeaders(const std::string &request, std::string &method,
                              std::string &path, std::string &body,
                              bool &accept_enc);

  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &headers_map);

private:
  std::unique_ptr<TcpServer> tcp_server_;
  std::unique_ptr<QuicServer> quic_server_;

  std::shared_ptr<Router> router_;

  std::shared_ptr<StaticContentHandler> static_content_handler_;

  std::mutex strerrorMutex;

  std::string threadSafeStrerror(int errnum);

  std::unordered_map<HQUIC, std::vector<uint8_t>> conn_settings_;
};

#endif // HTTPSERVER_HPP
