// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file router.h
 * @brief Defines the `Router` class and supporting structures for HTTP request
 * routing.
 *
 * This file contains the `Router` class which is responsible for managing
 * routes and dispatching HTTP requests to the appropriate handlers based on the
 * HTTP method and path.
 */

#ifndef INCLUDE_ROUTER_H_
#define INCLUDE_ROUTER_H_
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>

#include "../include/utils.h"

/**
 * @struct pair_hash
 * @brief A custom hash function for `std::pair`.
 *
 * This structure provides a hash function for `std::pair` that allows it to be
 * used as a key in `std::unordered_map`. It combines the hash values of the two
 * elements in the pair.
 */
struct pair_hash {
  /**
   * @brief Custom hash function for `std::pair<T1, T2>`.
   *
   * This function computes a combined hash for the two elements in the pair by
   * hashing each element individually and then combining the results.
   *
   * @tparam T1 The type of the first element in the pair.
   * @tparam T2 The type of the second element in the pair.
   * @param pairT The pair of elements to hash.
   * @return A combined hash value for the pair.
   */
  template <typename T1, typename T2>
  std::size_t operator()(const std::pair<T1, T2> &pairT) const {
    auto hash1 = std::hash<T1>{}(pairT.first);
    auto hash2 = std::hash<T2>{}(pairT.second);
    return hash1 ^ (hash2 << 1);
  }
};

/**
 * @class Router
 * @brief Manages routing for HTTP requests.
 *
 * The `Router` class is responsible for mapping HTTP request methods and paths
 * to their corresponding handler functions. It allows adding routes and
 * dispatching requests based on the method and path.
 */
class Router {
 public:
  /**
   * @brief Default constructor for the `Router` class.
   */
  Router();

  /**
   * @brief Destructor for the `Router` class.
   */
  ~Router();

  /**
   * @brief Adds a route to the router.
   *
   * This method registers a route with a specified HTTP method, path, and a
   * handler function that will be executed when a request with the
   * corresponding method and path is received.
   *
   * @param method The HTTP method (e.g., "GET", "POST").
   * @param path The path for the route (e.g., "/home").
   * @param handler The handler function that should be called for the route.
   */
  void AddRoute(const std::string &method, const std::string &path,
                const ROUTE_HANDLER &handler);

  /**
   * @brief Routes a request to the appropriate handler.
   *
   * This method checks the request method and path, and if a matching route is
   * found, it invokes the corresponding handler function.
   *
   * @param method The HTTP method of the incoming request (e.g., "GET").
   * @param path The path of the incoming request (e.g., "/home").
   * @param data The optional request data (e.g., POST body, query parameters).
   * @return A pair consisting of the response status and data.
   */
  std::pair<std::string, std::string> RouteRequest(
      const std::string &method, const std::string &path,
      const std::string &data = "");

 private:
  /**
   * @brief A map of routes, where each key is a pair of method and path, and
   * the value is the corresponding route handler.
   *
   * This map stores all registered routes and allows quick lookup based on
   * method and path.
   */
  std::unordered_map<std::pair<std::string, std::string>, ROUTE_HANDLER,
                     pair_hash>
      routes_;

  /**
   * @brief A static method that handles bad requests.
   *
   * This method is used as the default handler for requests that do not match
   * any registered route.
   *
   * @param data Optional data to return with the bad request response.
   * @return A pair consisting of a status message ("400 Bad Request") and the
   * optional data.
   */
  static std::pair<std::string, std::string> handleBadRequest(
      const std::string &data = "");
};

#endif  // INCLUDE_ROUTER_H_
