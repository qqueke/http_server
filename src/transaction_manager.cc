#include "../include/transaction_manager.h"

#include <iostream>
#include <mutex>
#include <string>

#include "../include/log.h"
#include "database_tables.h"

void TransactionManager::BeginTransaction() {
  std::lock_guard<std::mutex> lock(tx_mut_);
  // std::cout << "Begining transaction...\n";
  in_transaction_ = true;
  // Clear any possible undo_buffer Entries
  undo_buffer_.clear();
}

int TransactionManager::ProcessTransaction(const std::string &table_name,
                                           TableOp op,
                                           const std::string &data) {
  std::lock_guard<std::mutex> lock(tx_mut_);
  if (!in_transaction_) {
    return -1;
  }

  auto table_it = tables_collection_.find(table_name);
  if (table_it == tables_collection_.end()) {
    return -1;
  }

  auto &[table_n, table] = *table_it;
  if (op == TableOp::DELETE) {
    auto exists = table->GetAddDataFromDeleteKey(data);
    if (!exists.has_value()) {
      return -1;
    }

    std::cout << "Data placed for add rollback: " << exists.value()
              << std::endl;

    undo_buffer_.emplace_back(table_name, op, exists.value());
    return table->Delete(data);
  } else if (op == TableOp::ADD) {
    int ret = table->Add(data);
    if (ret != 0) {
      return ret;
    }
    // Operation succeded so lets add to the undo_log
    std::cout << "Data placed for delete rollback: "
              << table->GetDeleteKeyFromAddData(data) << std::endl;
    undo_buffer_.emplace_back(table_name, op,
                              table->GetDeleteKeyFromAddData(data));
    return ret;
  }

  return -1;  // Unknown transaction type
}

void TransactionManager::Commit() {
  std::lock_guard<std::mutex> lock(tx_mut_);
  in_transaction_ = false;
  undo_buffer_.clear();
}

void TransactionManager::Rollback() {
  std::lock_guard<std::mutex> lock(tx_mut_);
  std::cout << "Rolling back transaction...\n";

  for (auto it = undo_buffer_.rbegin(); it != undo_buffer_.rend(); ++it) {
    auto table_it = tables_collection_.find(it->table_name);
    if (table_it == tables_collection_.end()) {
      continue;
    }
    auto &[table_name, table] = *table_it;
    if (it->op == TableOp::ADD) {
      table->Delete(it->data);
    } else if (it->op == TableOp::DELETE) {
      table->Add(it->data);
    }
  }
  undo_buffer_.clear();
  in_transaction_ = false;
}
