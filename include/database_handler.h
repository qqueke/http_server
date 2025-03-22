// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file database_handler.h
 * @brief Defines the DatabaseHandler class for processing database queries.
 *
 * This file declares the `DatabaseHandler` class, which serves as an interface
 * between external requests and the database system. It handles query
 * validation, query building, and communication with the database client.
 */

#ifndef INCLUDE_DATABASE_HANDLER_H_
#define INCLUDE_DATABASE_HANDLER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "../include/database_client.h"
#include "../include/query_builder.h"
#include "../include/query_validator.h"

/**
 * @class DatabaseHandler
 * @brief Handles query processing, validation, and database communication.
 *
 * The `DatabaseHandler` class acts as a middle layer between external API
 * requests and the underlying database system. It is responsible for:
 * - Parsing incoming queries.
 * - Validating query structure.
 * - Constructing properly formatted database requests.
 * - Communicating with the `DatabaseClient` to execute queries.
 */
class DatabaseHandler {
 public:
  /**
   * @brief Constructor for the `DatabaseHandler` class.
   *
   * Initializes the database client, query builder, and query validators.
   */
  DatabaseHandler();

  /**
   * @brief Destructor for the `DatabaseHandler` class.
   */
  ~DatabaseHandler();

  /**
   * @brief Handles a query and returns a response with string headers.
   *
   * This method processes a database query using string-based headers,
   * validates the request, and communicates with the database client.
   *
   * @param method The HTTP method of the request (e.g., "GET", "POST").
   * @param path The endpoint or table name being queried.
   * @param data The query payload in JSON format (optional).
   * @return A pair containing:
   *         - The response headers as a string.
   *         - The response body as a string.
   */
  std::pair<std::string, std::string> HandleQueryWithStringHeaders(
      const std::string &method, const std::string &path,
      const std::string &data = "");

  /**
   * @brief Handles a query and returns a response with map headers.
   *
   * This method processes a database query using a map-based header structure,
   * validates the request, and interacts with the database client.
   *
   * @param method The HTTP method of the request (e.g., "GET", "POST").
   * @param path The endpoint or table name being queried.
   * @param data The query payload in JSON format (optional).
   * @return A pair containing:
   *         - A map of response headers.
   *         - The response body as a string.
   */
  std::pair<std::unordered_map<std::string, std::string>, std::string>
  HandleQueryWithMapHeaders(const std::string &method, const std::string &path,
                            const std::string &data = "");

  /**
   * @brief The database client responsible for sending queries to the database.
   */
  std::unique_ptr<DatabaseClient> db_client_;

 private:
  /**
   * @brief The query builder used to construct database queries.
   */
  std::unique_ptr<QueryBuilder> query_builder_;

  /**
   * @brief A collection of query validators for different database tables.
   *
   * This unordered map associates table names with their respective query
   * validators, ensuring that queries are correctly formatted before execution.
   */
  std::unordered_map<std::string, std::unique_ptr<ITableQueryValidator>>
      query_validator_;
};

#endif  // INCLUDE_DATABASE_HANDLER_H_
