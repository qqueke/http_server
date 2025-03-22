// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/router.h"

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

#include "../include/utils.h"

// Default initializer adds default routes
Router::Router() {
  routes_ = std::make_unique<Routes>();
  AddStringHeaderRoute("BR", "", HandleBadRequest);
  AddMapHeaderRoute("BR", "", OptHandleBadRequest);
}

Router::~Router() = default;

void Router::AddStringHeaderRoute(const std::string &method,
                                  const std::string &path,
                                  const ROUTE_HANDLER &handler) {
  auto key = std::make_pair(method, path);
  if (string_headers_routes_map_.find(key) !=
      string_headers_routes_map_.end()) {
    return;
  }

  string_headers_routes_map_[key] = handler;
}

void Router::AddMapHeaderRoute(const std::string &method,
                               const std::string &path,
                               const OPT_ROUTE_HANDLER &handler) {
  auto key = std::make_pair(method, path);
  if (map_headers_routes_map_.find(key) != map_headers_routes_map_.end()) {
    return;
  }

  std::cout << "Added opt route: " << method << " " << path << std::endl;
  map_headers_routes_map_[key] = handler;
}

std::optional<
    std::pair<std::unordered_map<std::string, std::string>, std::string>>
Router::RouteRequestWithMapHeaders(const std::string &method,
                                   const std::string &path,
                                   const std::string &data) {
  std::pair<std::string, std::string> route_key = std::make_pair(method, path);

  // Check if route exists in optimized routes for pseudo headers
  if (map_headers_routes_map_.find(route_key) !=
      map_headers_routes_map_.end()) {
    return map_headers_routes_map_[route_key](data);
  }

  // Check if route exists at all
  if (string_headers_routes_map_.find(route_key) ==
      string_headers_routes_map_.end()) {
    return OptHandleBadRequest(data);
  }

  return std::nullopt;
}

std::pair<std::string, std::string> Router::RouteRequestWithStringHeaders(
    const std::string &method, const std::string &path,
    const std::string &data) {
  std::pair<std::string, std::string> route_key = std::make_pair(method, path);

  if (string_headers_routes_map_.find(route_key) !=
      string_headers_routes_map_.end()) {
    return string_headers_routes_map_[route_key](data);
  }

  return HandleBadRequest();
}

std::pair<std::unordered_map<std::string, std::string>, std::string>
Router::OptHandleBadRequest(const std::string &data) {
  std::unordered_map<std::string, std::string> headers_map;
  headers_map[":status"] = "200";

  std::string body = "Bad Request\n";

  return {headers_map, body};
}

std::pair<std::string, std::string> Router::HandleBadRequest(
    const std::string &data) {
  std::string headers =
      "HTTP/1.1 200 Bad Request\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 12\r\n"
      "Connection: close\r\n"
      "\r\n";

  std::string body = "Bad Request\n";

  return {headers, body};
}
