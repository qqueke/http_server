// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.
#include "../include/database_handler.h"

#include <grpc/grpc.h>

#include <memory>

#include "../build/proto/database_service.pb.h"
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
  std::string operation = query_builder_->GetOperationType(method);

  std::unordered_map<std::string, std::string> headers_map;

  // Not very verbose. Ideally the database would formulate a string in case of
  // error
  int ret = db_client_->Send(operation, path, data);
  switch (ret) {
    case Code::SUCCESS:
      headers_map[":status"] = "200";
      break;
    case Code::NOT_FOUND:
      headers_map[":status"] = "404";
      break;
    case Code::ALREADY_EXISTS:
      headers_map[":status"] = "409";
      break;
    default:
      headers_map[":status"] = "500";
      break;
  }

  // Something that given query and error code constructs headers and body
  return {headers_map, ""};
}

std::pair<std::string, std::string> DatabaseHandler::HandleQuery(
    const std::string &method, const std::string &path,
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
