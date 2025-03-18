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
    instance_ = shared_instance;
  }
  return shared_instance;
}

int Database::Add(const std::string &table_name, const std::string &data) {
  if (tables_collection_.find(table_name) == tables_collection_.end()) {
    return -1;
  }
  return tables_collection_[table_name]->Add(data);
}

int Database::Delete(const std::string &table_name, const std::string &data) {
  if (tables_collection_.find(table_name) == tables_collection_.end()) {
    return -1;
  }
  return tables_collection_[table_name]->Delete(data);
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
  tables_collection_["/db/customers"] = std::make_unique<CustomersTable>();
}

Database::~Database() { std::cout << "Database connection closed" << '\n'; }
