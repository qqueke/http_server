// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file database_client.h
 * @brief Defines the DatabaseClient class for communicating with a gRPC
 * database server.
 *
 * This file declares the `DatabaseClient` class, which provides an interface
 * for sending database queries to a remote gRPC-based database service.
 */

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

/**
 * @class DatabaseClient
 * @brief Handles gRPC communication with a remote database server.
 *
 * The `DatabaseClient` class provides methods to interact with a remote
 * database service using gRPC. It allows sending database queries such as
 * adding, deleting, and searching for records.
 */
class DatabaseClient {
 public:
  /**
   * @brief Constructs a DatabaseClient with a specified gRPC channel.
   *
   * Establishes a connection with the remote database service via gRPC.
   *
   * @param channel A shared pointer to the gRPC channel used for communication.
   */
  explicit DatabaseClient(std::shared_ptr<grpc::Channel> channel);

  /**
   * @brief Sends a request to the database service.
   *
   * This method sends an operation (e.g., ADD, DELETE, SEARCH) along with the
   * target table name and the associated data.
   *
   * @param operation The type of database operation (e.g., "ADD", "DELETE",
   * "SEARCH").
   * @param table The name of the table to operate on.
   * @param data JSON-formatted data for the operation.
   * @return 0 on success, non-zero on failure.
   */
  int Send(const std::string &operation, const std::string &table,
           const std::string &data);

 private:
  /**
   * @brief The gRPC stub for interacting with the remote database service.
   */
  std::unique_ptr<DatabaseService::Stub> stub_;
};

#endif  // INCLUDE_DATABASE_CLIENT_H_
