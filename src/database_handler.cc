// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.
#include "../include/database_handler.h"

#include <grpc/grpc.h>

#include <memory>

#include "../include/database_client.h"

DatabaseHandler::DatabaseHandler() {
  db_client_ = std::make_unique<DatabaseClient>(grpc::CreateChannel(
      "localhost:9999", grpc::InsecureChannelCredentials()));
}

DatabaseHandler::~DatabaseHandler() { std::cout << "Destructing\n"; }

std::pair<std::unordered_map<std::string, std::string>, std::string>
DatabaseHandler::OptHandleQuery(const std::string &method,
                                const std::string &path,
                                const std::string &data) {
  std::string query = query_builder_->BuildQuery(method, path, data);

  int ret = db_client_->Send(query, path, data);

  // Check possible errors

  // Something that given query and error code constructs headers and body
  std::unordered_map<std::string, std::string> headers_map;
  headers_map[":status"] = "200";
  return {headers_map, ""};
}

std::pair<std::string, std::string> DatabaseHandler::HandleQuery(
    const std::string &method, const std::string &path,
    const std::string &data) {
  std::string query = query_builder_->BuildQuery(method, path, data);

  int ret = db_client_->Send(query, path, data);

  // Check possible errors

  // Something that given query and error code constructs headers and body
  std::string headers = "HTTP/1.1 200 OK";
  return {headers, ""};
}

// int main() {
//   DatabaseHandler db_handler;
//   db_handler.HandleQuery("POST", "mongos", "Ana");
//   return 0;
// }
