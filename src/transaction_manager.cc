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
  // std::cout << "Table name: " << table_n << "\n";
  if (op == TableOp::DELETE) {
    auto exists = table->GetEntryFromIndex(data);
    if (!exists.has_value()) {
      return -1;
    }

    undo_buffer_.emplace_back(table_name, op, exists.value());
    return table->Delete(data);
  } else if (op == TableOp::ADD) {
    std::optional<std::string> exists = table->GetIndexFromEntry(data);
    if (exists.has_value()) {
      return -1;  // Rejecting duplicates
    }
    // std::cout << "Data placed: " << table->GetIndexFromAddData(data)
    //           << std::endl;
    undo_buffer_.emplace_back(table_name, op, table->GetIndexFromAddData(data));
    return table->Add(data);
  }
  // Whenever we want search to be atomic across tables (for SQL for instance),
  // then we can implement it

  // LogError("Unknown transaction type: " + std::to_string(op));
  return -1;  // Unknown transaction type
}

void TransactionManager::Commit() {
  // std::cout << "Trying to commit...\n";
  std::lock_guard<std::mutex> lock(tx_mut_);
  // std::cout << "Committing transaction...\n";
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
      // std::cout << "Delete data : " << it->data << std::endl;
      table->Delete(it->data);
    } else if (it->op == TableOp::DELETE) {
      // std::cout << "Adding data back: " << it->data << std::endl;
      table->Add(it->data);
    }
  }
  undo_buffer_.clear();
  in_transaction_ = false;
}
