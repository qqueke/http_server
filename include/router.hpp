#ifndef ROUTER_HPP
#define ROUTER_HPP

#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cassert>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>

#include "utils.hpp"
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
  ~Router();

  void AddRoute(const std::string &method, const std::string &path,
                const ROUTE_HANDLER &handler);

  STATUS_CODE RouteRequest(const std::string &method, const std::string &path,
                           const std::string &data, Protocol protocol,
                           void *context);

private:
  // Routes receive string data, Protocol, void* Context, and Cache key for
  // caching purposes Route map with method-path pairs
  std::unordered_map<std::pair<std::string, std::string>, ROUTE_HANDLER,
                     pair_hash>
      routes;

  // Some default handles
  static STATUS_CODE handleBadRequest(const std::string &data,
                                      Protocol protocol, void *context,
                                      const std::string &cacheKey);

  static void SendResponse(std::string &headers, Protocol protocol,
                           void *context);

  static void SendResponse(std::string &headers, std::string &body,
                           Protocol protocol, void *context);
};

#endif // ROUTER_HPP
