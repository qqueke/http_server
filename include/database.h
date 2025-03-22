// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file database.h
 * @brief Defines the Database class, which manages database operations and
 * transactions.
 *
 * This file declares the `Database` class, which implements a singleton
 * database management system. It provides methods for executing queries,
 * handling transactions, and interacting with different database tables.
 */

#ifndef INCLUDE_DATABASE_H_
#define INCLUDE_DATABASE_H_

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "../include/database_tables.h"
#include "../include/transaction_manager.h"

/**
 * @class Database
 * @brief Manages database tables and transaction operations.
 *
 * The `Database` class is a **singleton** that provides methods for interacting
 * with database tables, executing queries, and managing transactions. It
 * ensures thread-safe access using a **mutex** and prevents multiple instances
 * via the singleton pattern.
 */
class Database {
 public:
  /**
   * @brief Destructor for the Database class.
   */
  ~Database();

  /**
   * @brief Deletes the copy constructor to enforce singleton behavior.
   */
  Database(const Database &) = delete;

  /**
   * @brief Deletes the copy assignment operator to enforce singleton behavior.
   */
  Database &operator=(const Database &) = delete;

  /**
   * @brief Returns a shared instance of the Database.
   *
   * Implements the singleton pattern using a weak pointer to ensure a single
   * instance is created and shared across the application.
   *
   * @return A shared pointer to the singleton Database instance.
   */
  static std::shared_ptr<Database> GetInstance();

  /**
   * @brief Searches for data in the specified table.
   *
   * This method looks up a table by name and executes a search query with the
   * given data.
   *
   * @param table_name The name of the table to search in.
   * @param data JSON-formatted search criteria.
   * @return The search result as a JSON-formatted string if found, otherwise an
   * empty optional.
   */
  std::optional<std::string> Search(const std::string &table_name,
                                    const std::string &data);

  /**
   * @brief Begins a new transaction.
   *
   * Initializes a transaction, allowing multiple operations to be grouped
   * together before being committed or rolled back.
   */
  void BeginTransaction();

  /**
   * @brief Adds an operation to the active transaction.
   *
   * @param table_name The name of the table on which the operation is
   * performed.
   * @param op The operation type (e.g., ADD, DELETE).
   * @param data JSON-formatted data for the operation.
   * @return 0 on success, non-zero on failure.
   */
  int AddToTransaction(const std::string &table_name, TableOp op,
                       const std::string &data);

  /**
   * @brief Commits the active transaction.
   *
   * Applies all changes made in the current transaction to the database.
   */
  void CommitTransaction();

  /**
   * @brief Rolls back the active transaction.
   *
   * Reverts all changes made in the current transaction.
   */
  void RollbackTransaction();

  /**
   * @brief Checks if a table exists in the database.
   *
   * @param table_name The name of the table to check.
   * @return True if the table exists, otherwise false.
   */
  bool TableExists(const std::string &table_name);

 private:
  /**
   * @brief Private constructor to enforce singleton behavior.
   */
  Database();

  /**
   * @brief Weak pointer to store the singleton instance.
   */
  static std::weak_ptr<Database> instance_;

  /**
   * @brief Mutex to ensure thread-safe singleton instantiation.
   */
  static std::mutex instance_mut_;

  /**
   * @brief Collection of database tables.
   *
   * Maps table names to `ITable` instances, allowing access to different
   * tables.
   */
  std::unordered_map<std::string, std::shared_ptr<ITable>> tables_collection_;

  /**
   * @brief Unique pointer to manage database transactions.
   */
  std::unique_ptr<TransactionManager> tx_manager_;
};

#endif  // INCLUDE_DATABASE_H_
