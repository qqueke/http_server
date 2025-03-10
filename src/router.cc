// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/router.h"

#include <string>
#include <utility>

#include "../include/utils.h"

// Default initializer adds default routes
Router::Router() { AddRoute("BR", "", handleBadRequest); }
Router::~Router() = default;

void Router::AddRoute(const std::string &method, const std::string &path,
                      const ROUTE_HANDLER &handler) {
  routes_[{method, path}] = handler;
}

std::pair<std::string, std::string>
Router::RouteRequest(const std::string &method, const std::string &path,
                     const std::string &data) {
  // std::cout << "Method: " << method << " Path: " << path << " Data: " << data
  //           << std::endl;

  std::pair<std::string, std::string> routeKey = std::make_pair(method, path);

  if (routes_.find(routeKey) != routes_.end()) {
    return routes_[routeKey](data);
  }

  return handleBadRequest();
}

std::pair<std::string, std::string>
Router::handleBadRequest(const std::string &data) {
  std::string headers = "HTTP/1.1 200 Bad Request\r\n"
                        // "Content-Type: text/plain\r\n"
                        // "Content-Length: 12\r\n"
                        // "Connection: close\r\n"
                        "\r\n";

  std::string body = "Bad Request\n";

  return {headers, body};
}
