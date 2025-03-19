// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.
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
class QueryBuilder {
 public:
  std::string GetOperationType(const std::string &method);

 private:
  static constexpr std::array<std::pair<std::string_view, std::string_view>, 3>
      kMethod_map_ = {
          {{"GET", "SEARCH"}, {"POST", "ADD"}, {"DELETE", "DELETE"}}};
};

#endif  // INCLUDE_QUERY_BUILDER_H_
