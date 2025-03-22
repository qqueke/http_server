// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.
#ifndef INCLUDE_DATABASE_HANDLER_H_
#define INCLUDE_DATABASE_HANDLER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "../include/database_client.h"
#include "../include/query_builder.h"
#include "../include/query_validator.h"

class DatabaseHandler {
 public:
  /**
   * @brief Constructor for the `DatabaseHandler` class.
   */
  DatabaseHandler();

  /**
   * @brief Destructor for the `DatabaseHandler` class.
   */
  ~DatabaseHandler();

  std::pair<std::string, std::string> HandleQueryWithStringHeaders(
      const std::string &method, const std::string &path,
      const std::string &data = "");

  std::pair<std::unordered_map<std::string, std::string>, std::string>
  HandleQueryWithMapHeaders(const std::string &method, const std::string &path,
                            const std::string &data = "");

  std::unique_ptr<DatabaseClient> db_client_;

 private:
  // Query builder
  std::unique_ptr<QueryBuilder> query_builder_;

  std::unordered_map<std::string, std::unique_ptr<ITableQueryValidator>>
      query_validator_;
};

#endif  // INCLUDE_DATABASE_HANDLER_H_
