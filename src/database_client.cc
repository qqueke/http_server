#include "../include/database_client.h"

#include <grpc/grpc.h>
#include <grpcpp/completion_queue.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <iostream>
#include <memory>
#include <string>

#include "../build/proto/database_service.grpc.pb.h"
#include "../build/proto/database_service.pb.h"

DatabaseClient::DatabaseClient(std::shared_ptr<grpc::Channel> channel)
    : stub_(DatabaseService::NewStub(channel)) {}

int DatabaseClient::Send(const std::string &operation, const std::string &table,
                         const std::string &data) {
  // Create request
  Query query;
  query.set_operation(operation);
  query.set_table(table);
  query.set_data(data);

  // Response
  Status response;

  // Context
  grpc::ClientContext context;

  // Call RPC
  grpc::Status status = stub_->ProcessQuery(&context, query, &response);

  if (status.ok()) {
    std::cout << "Server Response: " << response.value() << std::endl;
  } else {
    std::cout << "RPC failed: " << status.error_message() << std::endl;
  }

  return 0;
}

// int main() {
//   // Create a channel to connect to the server
//   DatabaseClient client(grpc::CreateChannel(
//       "localhost:9999", grpc::InsecureChannelCredentials()));
//
//   // Call the RPC method
//   client.Send("INSERT");
//
//   return 0;
// }
