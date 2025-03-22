// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_DATABASE_H_
#define INCLUDE_DATABASE_H_
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

#include "../include/database_tables.h"
#include "../include/transaction_manager.h"

class Database {
 public:
  ~Database();

  Database(const Database &) = delete;

  Database &operator=(const Database &) = delete;

  static std::shared_ptr<Database> GetInstance();

  std::optional<std::string> Search(const std::string &table_name,
                                    const std::string &data);

  void BeginTransaction();

  int AddToTransaction(const std::string &table_name, TableOp op,
                       const std::string &data);

  void CommitTransaction();

  void RollbackTransaction();

  bool TableExists(const std::string &table_name);

 private:
  Database();

  static std::weak_ptr<Database> instance_;

  static std::mutex instance_mut_;

  std::unordered_map<std::string, std::shared_ptr<ITable>> tables_collection_;

  std::unique_ptr<TransactionManager> tx_manager_;
};

#endif  // INCLUDE_DATABASE_H_
