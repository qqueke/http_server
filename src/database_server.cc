#include <grpc/grpc.h>
#include <grpcpp/completion_queue.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <memory>
#include <optional>

#include "../build/proto/database_service.grpc.pb.h"
#include "../build/proto/database_service.pb.h"
#include "../include/database.h"

class DatabaseImpl : public DatabaseService::Service {
 public:
  explicit DatabaseImpl(const std::shared_ptr<Database> &db) : db_(db) {}

  ::grpc::Status ProcessQuery(::grpc::ServerContext *context,
                              const ::Query *query, ::Status *response) {
    std::cout << "Query: " << query->operation() << " in TABLE "
              << query->table() << " " << query->data() << std::endl;

    // From table choose the database
    if (query->operation() == "ADD") {
      int ret = db_.lock()->Add(query->table(), query->data());
      std::cout << ((ret == 0) ? "Added customer: "
                               : "Could not add customer: ")
                << query->data() << std::endl;
    } else if (query->operation() == "SEARCH") {
      auto c = db_.lock()->Search(query->table(), query->data());
      if (c != std::nullopt) {
        std::cout << "Found customer: " << c.value() << "\n";
      } else {
        std::cout << "Failed to find customer\n";
      }
    } else if (query->operation() == "DELETE") {
      int ret = db_.lock()->Delete(query->table(), query->data());
      std::cout << ((ret == 0) ? "Deleted customer: "
                               : "Could not delete customer: ")
                << query->data() << std::endl;
    }

    return grpc::Status::OK;
  }

 private:
  std::weak_ptr<Database> db_;
};

int main() {
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
