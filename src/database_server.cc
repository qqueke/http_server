// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include <grpc/grpc.h>
#include <grpcpp/completion_queue.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "../build/proto/database_service.grpc.pb.h"
#include "../build/proto/database_service.pb.h"
#include "../include/database.h"
#include "../include/database_tables.h"
#include "../include/log.h"

class DatabaseImpl : public DatabaseService::Service {
 public:
  explicit DatabaseImpl(const std::shared_ptr<Database> &db) : db_(db) {}

  ::grpc::Status ProcessQuery(::grpc::ServerContext *context,
                              const ::Query *query, ::Status *response) {
    std::cout << "Query: " << query->operation() << " in TABLE "
              << query->table() << " " << query->data() << std::endl;

    auto db_ptr = db_.lock();
    if (db_ptr == nullptr) {
      response->set_code(Code::DATABASE_ERROR);
      return grpc::Status::OK;
    } else if (!db_ptr->TableExists(query->table())) {
      std::cout << "Table: " << query->table() << " does not exist\n";
      response->set_code(Code::DATABASE_ERROR);
      return grpc::Status::OK;
    }
    // From table choose the database
    if (query->operation() == "ADD") {
      db_ptr->BeginTransaction();
      int ret =
          db_ptr->AddToTransaction(query->table(), TableOp::ADD, query->data());
      db_ptr->CommitTransaction();
      (ret == -1) ? response->set_code(Code::ALREADY_EXISTS)
                  : response->set_code(Code::SUCCESS);
    } else if (query->operation() == "SEARCH") {
      auto ret = db_ptr->Search(query->table(), query->data());
      (ret == std::nullopt) ? response->set_code(Code::NOT_FOUND)
                            : response->set_code(Code::SUCCESS);
    } else if (query->operation() == "DELETE") {
      db_ptr->BeginTransaction();
      int ret = db_ptr->AddToTransaction(query->table(), TableOp::DELETE,
                                         query->data());
      db_ptr->CommitTransaction();

      (ret == -1) ? response->set_code(Code::NOT_FOUND)
                  : response->set_code(Code::SUCCESS);
    }

    return grpc::Status::OK;
  }

 private:
  std::weak_ptr<Database> db_;
};

int main() {
  Logger::GetInstance("db_server.log");
  std::string target_str = "0.0.0.0:9999";

  std::shared_ptr<Database> db;
  db = Database::GetInstance();
  DatabaseImpl service(db);
  grpc::ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(target_str, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << target_str << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
  return 0;
}
