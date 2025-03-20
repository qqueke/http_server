#ifndef INCLUDE_TRANSACTION_MANAGER_H_
#define INCLUDE_TRANSACTION_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "database_tables.h"

class TransactionManager {
 public:
  explicit TransactionManager(
      std::unordered_map<std::string, std::shared_ptr<ITable>>
          &tables_collection)
      : tables_collection_(tables_collection) {}

  void BeginTransaction();

  int ProcessTransaction(const std::string &table_name, TableOp op,
                         const std::string &data);
  void Commit();

  void Rollback();

 private:
  struct UndoLogEntry {
    std::string table_name;
    TableOp op;
    std::string data;

    UndoLogEntry(const std::string &table_name, TableOp op,
                 const std::string &data)
        : table_name(table_name), op(op), data(data) {}
  };

  std::unordered_map<std::string, std::shared_ptr<ITable>> &tables_collection_;
  bool in_transaction_ = false;
  std::mutex tx_mut_;
  std::vector<UndoLogEntry> undo_buffer_;
};

#endif  // INCLUDE_TRANSACTION_MANAGER_H_
