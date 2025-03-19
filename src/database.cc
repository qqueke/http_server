#include "../include/database.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>

std::weak_ptr<Database> Database::instance_;

std::mutex Database::instance_mut_;

std::shared_ptr<Database> Database::GetInstance() {
  // Could use static instead of mut prob
  std::lock_guard<std::mutex> lock(instance_mut_);

  std::shared_ptr shared_instance = instance_.lock();
  if (shared_instance == nullptr) {
    shared_instance = std::shared_ptr<Database>(new Database());
    shared_instance->tx_manager_ = std::make_unique<TransactionManager>(
        shared_instance->tables_collection_);
    instance_ = shared_instance;
  }
  return shared_instance;
}

void Database::BeginTransaction() { tx_manager_->BeginTransaction(); }

int Database::AddToTransaction(const std::string &table_name, TableOp op,
                               const std::string &data) {
  return tx_manager_->ProcessTransaction(table_name, op, data);
}

void Database::CommitTransaction() { tx_manager_->Commit(); }

void Database::RollbackTransaction() { tx_manager_->Rollback(); }

bool Database::TableExists(const std::string &table_name) {
  return tables_collection_.find(table_name) != tables_collection_.end();
}

std::optional<std::string> Database::Search(const std::string &table_name,
                                            const std::string &data) {
  if (tables_collection_.find(table_name) == tables_collection_.end()) {
    return std::nullopt;
  }
  return tables_collection_[table_name]->Search(data);
}

Database::Database() {
  std::cout << "Creating new database\n";
  tables_collection_["customers"] = std::make_unique<CustomersTable>();
}

Database::~Database() { std::cout << "Database connection closed" << '\n'; }
