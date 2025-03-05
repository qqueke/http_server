
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

#include "common.hpp"
#include "framehandler.hpp"
#include "quicserver.hpp"
#include "router.hpp"
#include "tcpserver.hpp"

class HttpServer : public HttpCore,
                   public std::enable_shared_from_this<HttpServer> {
private:
  std::unique_ptr<TcpServer> tcpServer;
  std::unique_ptr<QuicServer> quicServer;

  std::mutex strerrorMutex;

  std::string threadSafeStrerror(int errnum);

  std::unordered_map<HQUIC, std::vector<uint8_t>> ConnectionSettings;

public:
  HttpServer(int argc, char *argv[]);

  ~HttpServer();

  std::unique_ptr<HttpCore> http;
  // std::unique_ptr<Router> router;
  std::shared_ptr<Router> router;

  void staticFileHandler(SSL *clientSSL, const std::string &filePath,
                         bool acceptEncoding);

  static void storeInCache(const std::string &cacheKey,
                           const std::string &response);

  void PrintFromServer();
  void AddRoute(const std::string &method, const std::string &path,
                const ROUTE_HANDLER &handler);
  void Run();

  static void ValidateHeaders(const std::string &request, std::string &method,
                              std::string &path, std::string &body,
                              bool &acceptEncoding);

  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &headersMap);
};

#endif // HTTPSERVER_HPP
