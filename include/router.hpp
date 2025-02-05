#ifndef ROUTER_HPP
#define ROUTER_HPP

#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <functional>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <string>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>

struct pair_hash {
  template <typename T1, typename T2>
  std::size_t operator()(const std::pair<T1, T2> &pairT) const {
    auto hash1 = std::hash<T1>{}(pairT.first);
    auto hash2 = std::hash<T2>{}(pairT.second);
    return hash1 ^ (hash2 << 1);
  }
};

class Router {
public:
  Router();
  Router(const Router &);
  Router &operator=(const Router &);

  void
  addRoute(const std::string &method, const std::string &path,
           const std::function<std::string(SSL *, const std::string)> &handler);
  std::string routeRequest(const std::string &method, const std::string &path,
                           SSL *clientSock);

  static void staticFileHandler(SSL *clientSSL, const std::string &filePath,
                                bool acceptEncoding);

  static void storeInCache(const std::string &cacheKey,
                           const std::string &response);

private:
  // Route map with method-path pairs
  std::unordered_map<std::pair<std::string, std::string>,
                     std::function<std::string(SSL *, const std::string)>,
                     pair_hash>
      routes;

  // Static helper functions for error handling
  static std::string handleMethodNotAllowed(SSL *clientSock,
                                            const std::string &cacheKey);
  static std::string handleNotFound(SSL *clientSock,
                                    const std::string &cacheKey);
  static std::string handleBadRequest(SSL *clientSock,
                                      const std::string &cacheKey);
  static std::string handleLengthRequired(SSL *clientSock,
                                          const std::string &cacheKey);
  static std::string handleUnsupportedProtocol(SSL *clientSock,
                                               const std::string &cacheKey);
  static std::string handleConnectionsLimit(SSL *clientSock,
                                            const std::string &cacheKey);

  static std::string handleValidationFailure(SSL *clientSock,
                                             const std::string &cacheKey);
};

#endif // ROUTER_HPP
