
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

  static HTTPServer *instance;
  static std::mutex instanceMutex;

  std::string threadSafeStrerror(int errnum);

  HTTPServer(int argc, char *argv[]);

  void
  clientHandlerThread(int clientSock,
                      std::chrono::high_resolution_clock::time_point startTime);

  void RunHTTP1();
  void RunHTTP2();
  void RunHTTP3();

public:
  static void Initialize(int argc, char *argv[]);
  static HTTPServer *GetInstance();

  std::unordered_map<HQUIC, std::vector<uint8_t>> BufferMap;
  std::unique_ptr<Router> ServerRouter;
  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      DecodedHeadersMap;

  HTTPServer(const HTTPServer &) = delete;
  HTTPServer(HTTPServer &&) = delete;
  HTTPServer &operator=(const HTTPServer &) = delete;
  HTTPServer &operator=(HTTPServer &&) = delete;
  ~HTTPServer();

  static int dhiProcessHeader(void *hblock_ctx, struct lsxpack_header *xhdr);

  static void UQPACKHeadersServer(HQUIC stream,
                                  std::vector<uint8_t> &encodedHeaders);

  static void ParseStreamBuffer(HQUIC Stream,
                                std::vector<uint8_t> &streamBuffer,
                                std::string &data);

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
      std::unordered_map<std::string, std::string> &headersMap);

  static int SendHTTP1Response(SSL *clientSSL, const std::string &response);

  static int SendHTTP3Response(HQUIC Stream,
                               std::vector<std::vector<uint8_t>> &frames);
};

#endif // HTTPSERVER_HPP
