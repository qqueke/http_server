// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.
#include "../include/database_handler.h"

#include <grpc/grpc.h>

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

#include "../build/proto/database_service.pb.h"
#include "../include/customers_table_validator.h"
#include "../include/database_client.h"

DatabaseHandler::DatabaseHandler() {
  db_client_ = std::make_unique<DatabaseClient>(grpc::CreateChannel(
      "localhost:9999", grpc::InsecureChannelCredentials()));
  query_validator_["customers"] = std::make_unique<CustomersTableValidator>();
}

DatabaseHandler::~DatabaseHandler() { std::cout << "Destructing\n"; }

std::pair<std::unordered_map<std::string, std::string>, std::string>
DatabaseHandler::HandleQueryWithMapHeaders(const std::string &method,
                                           const std::string &path,
                                           const std::string &data) {
  std::unordered_map<std::string, std::string> headers_map;
  std::string body;

  if (query_validator_.find(path) == query_validator_.end()) {
    std::cout << "Table not found: " << path << '\n';
    headers_map[":status"] = "404";
    body = "Table not found\n";
    return {headers_map, body};
  }

  std::string operation = query_builder_->GetOperationType(method);
  auto validate = query_validator_[path]->ValidateQuery(operation, data);
  if (validate != std::nullopt) {
    std::cout << "Request failed validation: " << validate.value() << '\n';
    headers_map[":status"] = "400";
    body = validate.value() + "\n";
    return {headers_map, body};
  }

  // Not very verbose. Ideally the database would formulate a string in case of
  // error
  int ret = db_client_->Send(operation, path, data);
  switch (ret) {
    case Code::SUCCESS:
      headers_map[":status"] = "200";
      break;
    case Code::NOT_FOUND:
      headers_map[":status"] = "404";
      body = data + " not found\n";
      break;
    case Code::ALREADY_EXISTS:
      headers_map[":status"] = "409";
      body = data + " already exists\n";
      break;
    default:
      headers_map[":status"] = "500";
      body = "Internal Error\n";
      break;
  }

  return {headers_map, body};
}

std::pair<std::string, std::string>
DatabaseHandler::HandleQueryWithStringHeaders(const std::string &method,
                                              const std::string &path,
                                              const std::string &data) {
  std::string operation = query_builder_->GetOperationType(method);

  int ret = db_client_->Send(operation, path, data);

  std::string headers;

  switch (ret) {
    case Code::SUCCESS:
      headers = "HTTP/1.1 200 OK";
      break;
    case Code::NOT_FOUND:
      headers = "HTTP/1.1 404 Not Found";
      break;
    case Code::ALREADY_EXISTS:
      headers = "HTTP/1.1 409 Conflict";
      break;
    default:
      headers = "HTTP/1.1 500 Internal Server Error";
      break;
  }

  // Something that given query and error code constructs headers and body
  return {headers, ""};
}

// int main() {
//   DatabaseHandler db_handler;
//   db_handler.HandleQuery("POST", "mongos", "Ana");
//   return 0;
// }
