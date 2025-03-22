// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_DATABASE_CLIENT_H_
#define INCLUDE_DATABASE_CLIENT_H_

#include <grpc/grpc.h>
#include <grpcpp/completion_queue.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <memory>
#include <string>

#include "../build/proto/database_service.grpc.pb.h"
#include "../build/proto/database_service.pb.h"

class DatabaseClient {
 public:
  explicit DatabaseClient(std::shared_ptr<grpc::Channel> channel);

  int Send(const std::string &operation, const std::string &table,
           const std::string &data);

 private:
  std::unique_ptr<DatabaseService::Stub> stub_;
};

#endif  // INCLUDE_DATABASE_CLIENT_H_
