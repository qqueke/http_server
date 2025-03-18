// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/query_builder.h"

#include <array>

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

std::string_view QueryBuilder::GetOperationType(const std::string &method) {
  for (const auto &pair : kMethod_map_) {
    if (method == pair.first) {
      return pair.second;
    }
  }
  return "";
}

std::string QueryBuilder::BuildQuery(const std::string &method,
                                     const std::string &path,
                                     const std::string &body) {
  std::string query = std::string(GetOperationType(method));
  if (query == "") {
    return query;
  }

  return query;
}
