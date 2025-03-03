#ifndef ROUTER_HPP
#define ROUTER_HPP

#include <functional>

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

  std::pair<std::string, std::string>
  RouteRequest(const std::string &method, const std::string &path,
               const std::string &data = "");

private:
  // Change this so that instead of a pair we have concatenated string
  std::unordered_map<std::pair<std::string, std::string>, ROUTE_HANDLER,
                     pair_hash>
      routes;

  static std::pair<std::string, std::string>
  handleBadRequest(const std::string &data = "");
};

#endif // ROUTER_HPP
