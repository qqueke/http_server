
#ifndef HTTPSERVER_HPP
#define HTTPSERVER_HPP

#include "router.hpp"
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
#include <openssl/ssl.h>

enum : int {
  BUFFER_SIZE = 1024,
  ERROR = -1,
  TIMEOUT_SECONDS = 60,
  MAX_CONNECTIONS = 100,
  MAX_PENDING_CONNECTIONS = 100,
  HTTP_PORT = 443,
};

class HTTPServer {
private:
  std::atomic<int> activeConnections;
  int serverSock;
  sockaddr_in serverAddr;
  struct timeval timeout;
  std::unique_ptr<Router> router;
  std::mutex strerrorMutex;
  SSL_CTX *ctx;


  QUIC_STATUS Status;
  HQUIC Listener;
  QUIC_ADDR Address;

  std::string threadSafeStrerror(int errnum);
  int validateRequest(const std::string &request, std::string &method,
                      std::string &path, SSL *clientSock, bool &acceptEncoding);
  void
  clientHandlerThread(int clientSock,
                      std::chrono::high_resolution_clock::time_point startTime);

public:
  HTTPServer(int argc, char *argv[]);
  HTTPServer(const HTTPServer &) = delete;
  HTTPServer(HTTPServer &&) = delete;
  HTTPServer &operator=(const HTTPServer &) = delete;
  HTTPServer &operator=(HTTPServer &&) = delete;
  ~HTTPServer();

  void PrintFromServer();
  void
  addRoute(const std::string &method, const std::string &path,
           const std::function<std::string(SSL *, const std::string)> &handler);
  void run();
};

#endif // HTTPSERVER_HPP
