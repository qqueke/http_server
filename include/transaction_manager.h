// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file transaction_manager.h
 * @brief Defines the `TransactionManager` class for managing database
 * transactions.
 *
 * This file declares the `TransactionManager` class, which is responsible for
 * handling transactions in the database. The class allows for beginning,
 * processing, committing, and rolling back transactions. It also maintains an
 * undo log to support rolling back changes if necessary.
 */

#ifndef INCLUDE_TRANSACTION_MANAGER_H_
#define INCLUDE_TRANSACTION_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/database_tables.h"

/**
 * @class TransactionManager
 * @brief A class for managing database transactions.
 *
 * The `TransactionManager` class is responsible for managing database
 * transactions, including beginning a transaction, processing operations within
 * the transaction, and committing or rolling back the changes. It supports undo
 * functionality through an undo log.
 */
class TransactionManager {
 public:
  /**
   * @brief Constructor for the `TransactionManager` class.
   *
   * The constructor initializes the `TransactionManager` with the tables
   * collection, which is a reference to the map of database tables. This allows
   * the transaction manager to interact with the database tables during
   * transactions.
   *
   * @param tables_collection A reference to a collection of database tables.
   */
  explicit TransactionManager(
      std::unordered_map<std::string, std::shared_ptr<ITable>>
          &tables_collection);

  /**
   * @brief Begins a new transaction.
   *
   * This method starts a new transaction. After calling this method, database
   * operations can be processed as part of the transaction, and the changes can
   * either be committed or rolled back.
   */
  void BeginTransaction();

  /**
   * @brief Processes an operation within the current transaction.
   *
   * This method processes a database operation (ADD, DELETE, or SEARCH) on a
   * specific table as part of the ongoing transaction. The operation will be
   * recorded in the undo log to facilitate rolling back the transaction if
   * necessary.
   *
   * @param table_name The name of the table on which the operation is being
   * performed.
   * @param op The operation type (ADD, DELETE, SEARCH).
   * @param data The data associated with the operation.
   * @return An integer indicating the result of processing the operation.
   */
  int ProcessTransaction(const std::string &table_name, TableOp op,
                         const std::string &data);

  /**
   * @brief Commits the current transaction.
   *
   * This method commits the current transaction, applying all changes made
   * during the transaction to the database permanently.
   */
  void Commit();

  /**
   * @brief Rolls back the current transaction.
   *
   * This method rolls back the current transaction, undoing all changes made
   * during the transaction. The operation is supported by the undo log, which
   * stores all operations that can be reversed.
   */
  void Rollback();

 private:
  /**
   * @struct UndoLogEntry
   * @brief Represents a single entry in the undo log.
   *
   * The `UndoLogEntry` structure stores information about a single database
   * operation, including the table name, the operation type, and the data
   * involved. These entries allow the transaction manager to undo the changes
   * made during a transaction.
   */
  struct UndoLogEntry {
    std::string
        table_name;    ///< The name of the table involved in the operation.
    TableOp op;        ///< The operation type (ADD, DELETE, SEARCH).
    std::string data;  ///< The data involved in the operation.

    /**
     * @brief Constructor for the `UndoLogEntry` structure.
     *
     * Initializes an undo log entry with the specified table name, operation
     * type, and data.
     *
     * @param table_name The name of the table involved in the operation.
     * @param op The operation type (ADD, DELETE, SEARCH).
     * @param data The data involved in the operation.
     */
    UndoLogEntry(const std::string &table_name, TableOp op,
                 const std::string &data);
  };

  std::unordered_map<std::string, std::shared_ptr<ITable>>
      &tables_collection_;  ///< Reference to the tables collection.
  bool in_transaction_ =
      false;  ///< Flag indicating whether a transaction is in progress.
  std::mutex tx_mut_;  ///< Mutex to ensure thread-safety during transactions.
  std::vector<UndoLogEntry>
      undo_buffer_;  ///< The undo log buffer for the current transaction.
};

#endif  // INCLUDE_TRANSACTION_MANAGER_H_
