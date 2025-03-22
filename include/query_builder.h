// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file query_builder.h
 * @brief Defines the QueryBuilder class for determining the operation type
 * based on HTTP method.
 *
 * This file declares the `QueryBuilder` class, which provides functionality to
 * map HTTP methods (GET, POST, DELETE) to corresponding database operation
 * types (SEARCH, ADD, DELETE). It helps to dynamically determine the type of
 * database operation based on the HTTP request method.
 *
 * @author Your Name
 * @date 2025-03-22
 */

#ifndef INCLUDE_QUERY_BUILDER_H_
#define INCLUDE_QUERY_BUILDER_H_

/*
 * GET -> Search
 * POST -> Add
 * DELETE -> Delete
 * Path -> Database table
 * Body:
 * * GET -> customer_id or username
 * * POST -> "username, customer_name"
 * * DELETE -> customer_id or username
 * */

#include <array>
#include <string>

/**
 * @class QueryBuilder
 * @brief A utility class for mapping HTTP methods to database operations.
 *
 * The `QueryBuilder` class provides a method to determine the type of database
 * operation (SEARCH, ADD, DELETE) based on the HTTP method (GET, POST, DELETE).
 * This is useful in scenarios where HTTP requests are mapped to database
 * queries and operations.
 */
class QueryBuilder {
 public:
  /**
   * @brief Determines the database operation type based on the HTTP method.
   *
   * This method maps the given HTTP method (GET, POST, DELETE) to its
   * corresponding database operation type. It is used to dynamically determine
   * the operation type for executing database queries based on the HTTP request
   * method.
   *
   * @param method The HTTP method (e.g., "GET", "POST", "DELETE").
   * @return A string representing the corresponding database operation type
   * ("SEARCH", "ADD", "DELETE").
   */
  std::string GetOperationType(const std::string &method);

 private:
  /**
   * @brief A static map of HTTP methods to corresponding database operations.
   *
   * This map holds the correspondence between HTTP methods and database
   * operations:
   * - "GET" -> "SEARCH"
   * - "POST" -> "ADD"
   * - "DELETE" -> "DELETE"
   */
  static constexpr std::array<std::pair<std::string_view, std::string_view>, 3>
      kMethod_map_ = {
          {{"GET", "SEARCH"}, {"POST", "ADD"}, {"DELETE", "DELETE"}}};
};

#endif  // INCLUDE_QUERY_BUILDER_H_
