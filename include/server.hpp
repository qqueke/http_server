
#ifndef HTTPSERVER_HPP
#define HTTPSERVER_HPP

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
#include "router.hpp"

class HTTPServer {
private:
  std::atomic<int> activeConnections;
  int serverSock;
  sockaddr_in serverAddr;
  struct timeval timeout;
  std::mutex strerrorMutex;
  SSL_CTX *ctx;

  QUIC_STATUS Status;
  HQUIC Listener;
  QUIC_ADDR Address;

  std::string threadSafeStrerror(int errnum);

  void
  clientHandlerThread(int clientSock,
                      std::chrono::high_resolution_clock::time_point startTime);

  void RunHTTP1();
  void RunHTTP2();
  void RunHTTP3();

public:
  std::unordered_map<HQUIC, std::vector<uint8_t>> BufferMap;

  std::unique_ptr<Router> ServerRouter;
  HTTPServer(int argc, char *argv[]);
  HTTPServer(const HTTPServer &) = delete;
  HTTPServer(HTTPServer &&) = delete;
  HTTPServer &operator=(const HTTPServer &) = delete;
  HTTPServer &operator=(HTTPServer &&) = delete;
  ~HTTPServer();

  void staticFileHandler(SSL *clientSSL, const std::string &filePath,
                         bool acceptEncoding);

  static void storeInCache(const std::string &cacheKey,
                           const std::string &response);

  void PrintFromServer();
  void AddRoute(const std::string &method, const std::string &path,
                const ROUTE_HANDLER &handler);
  void Run();

  static int ValidateRequestsHTTP1(const std::string &request,
                                   std::string &method, std::string &path,
                                   bool &acceptEncoding);

  static void ValidateHeadersHTTP3(
      const std::string &headers,
      std::unordered_map<std::string, std::string> &headersMap);

  static int SendHTTP1Response(SSL *clientSSL, const std::string &response);

  static int SendHTTP3Response(HQUIC Stream,
                               std::vector<std::vector<uint8_t>> &frames);
};

#endif // HTTPSERVER_HPP
