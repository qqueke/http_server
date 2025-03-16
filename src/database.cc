#include "../include/database.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

std::weak_ptr<Database> Database::instance_;

std::mutex Database::instance_mut_;

std::shared_ptr<Database> Database::GetInstance() {
  std::lock_guard<std::mutex> lock(instance_mut_);

  std::shared_ptr shared_instance = instance_.lock();
  if (shared_instance == nullptr) {
    shared_instance = std::shared_ptr<Database>(new Database());
    instance_ = shared_instance;
  }
  return shared_instance;
}

std::string Database::GetRecordUsername(std::string_view line) {
  // Pass the field string by argument instead
  constexpr std::string_view username_field = "\"username\": \"";

  size_t start_pos = line.find(username_field);
  if (start_pos == std::string::npos) {
    return {};
  }

  start_pos += username_field.size();
  size_t end_pos = line.find('"', start_pos);
  if (end_pos == std::string::npos) {
    end_pos = line.find('}', start_pos);
  }

  std::string username =
      std::string(line.substr(start_pos, end_pos - start_pos));

  return username;
}

uint64_t Database::GetRecordId(std::string_view line) {
  // Pass the field string by argument instead
  constexpr std::string_view id_field = "_id\": ";

  size_t start_pos = line.find(id_field);
  if (start_pos == std::string::npos) {
    return 0;
  }

  start_pos += id_field.size();
  size_t end_pos = line.find(',', start_pos);
  if (end_pos == std::string::npos) {
    end_pos = line.find('}', start_pos);
  }

  uint64_t id =
      std::stoull(std::string(line.substr(start_pos, end_pos - start_pos)));

  return id;
}

void Database::InitializeIndexFromFile() {
  std::string line;
  std::ifstream in_file(customers_file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    uint64_t client_id = GetRecordId(line_view);
    curr_idx_ = (client_id > curr_idx_) ? client_id + 1 : curr_idx_ + 1;
  }
  std::cout << "Acquired idx:" << curr_idx_ << std::endl;
}

Database::Database() : curr_idx_(0) {
  std::cout << "Creating new database\n";
  const char *db_file_path = getenv("DATABASE");
  if (db_file_path != nullptr) {
    customers_file_path_ = std::string(db_file_path);
  } else {
    customers_file_path_ = "db.json";
  }

  const char *invalid_file_path = getenv("INVALID");
  if (invalid_file_path != nullptr) {
    invalid_customers_file_path_ = std::string(invalid_file_path);
  } else {
    invalid_customers_file_path_ = "invalid.json";
  }
  InitializeIndexFromFile();
}

Database::~Database() {
  std::cout << "Database connection closed" << std::endl;
}

int Database::RegisterCustomer(const Customer &customer) {
  std::cout << "customer username: " << customer.username << std::endl;
  // We need to check if the username is unique first
  if (Search4Customer(customer.username)) {
    std::cout << "Username already exists, skipping...\n";
    return -1;
  }

  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[index, buffer_customer] : buffer_) {
      if (buffer_customer.username == customer.username) {
        std::cout << "Username already exists in-memory\n";
        return -1;
      }
    }
  }

  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    buffer_.emplace(curr_idx_, customer);
  }
  FlushToFile();

  if (buffer_.size() >= 10) {
    FlushToFile();
  }
  return 0;
}

std::optional<Customer> Database::Search4Customer(
    const std::string &target_username) {
  // If still in memory, perfect
  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[index, customer] : buffer_) {
      if (customer.username == target_username) {
        return customer;
      }
    }
  }

  std::lock_guard<std::mutex> lock(customers_file_mut_);
  std::string line;
  std::ifstream in_file(customers_file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    std::string username = GetRecordUsername(line_view);

    if (username == target_username &&
        !IsInvalidCustomer(GetRecordId(line_view))) {
      return DeserializeCustomer(line_view);
    }
  }

  return std::nullopt;
}

std::optional<Customer> Database::Search4Customer(uint64_t target_id) {
  // If still in memory, perfect
  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    auto iter = buffer_.find(target_id);
    if (iter != buffer_.end()) {
      return iter->second;
    }
  }
  std::lock_guard<std::mutex> lock(customers_file_mut_);
  std::string line;
  std::ifstream in_file(customers_file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    uint64_t record_id = GetRecordId(line_view);

    if (record_id == target_id && !IsInvalidCustomer(target_id)) {
      return DeserializeCustomer(line_view);
    }
  }

  return std::nullopt;
}

Customer Database::DeserializeCustomer(std::string_view line) {
  constexpr std::string_view username_field = "\"username\": \"";

  size_t start_pos = line.find(username_field);
  if (start_pos == std::string::npos) {
    return {};
  }

  start_pos += username_field.size();
  size_t end_pos = line.find('"', start_pos);
  if (end_pos == std::string::npos) {
    return {};
  }

  std::string username =
      std::string(line.substr(start_pos, end_pos - start_pos));

  constexpr std::string_view customer_name_field = "\"customer_name\": \"";

  start_pos = line.find(customer_name_field);
  if (start_pos == std::string::npos) {
    return {};
  }

  start_pos += customer_name_field.size();
  end_pos = line.find('"', start_pos);
  if (end_pos == std::string::npos) {
    return {};
  }

  std::string customer_name =
      std::string(line.substr(start_pos, end_pos - start_pos));

  return {username, customer_name};
}

int Database::DeleteCustomer(const uint64_t target_id) {
  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    auto iter = buffer_.find(target_id);
    if (iter != buffer_.end()) {
      buffer_.erase(iter);
      return 0;
    }
  }
  std::lock_guard<std::mutex> lock(customers_file_mut_);
  // If not in the buffer then we need to check the file
  std::string line;
  std::ifstream in_file(customers_file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    uint64_t record_id = GetRecordId(line_view);

    if (record_id == target_id && !IsInvalidCustomer(target_id)) {
      std::cout << "Deleting client with id: " << target_id << "\n";
      InvalidateCustomer(line_view);
      return 0;
    }
  }

  return -1;
}

int Database::DeleteCustomer(const std::string &target_username) {
  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[index, customer] : buffer_) {
      if (customer.username == target_username) {
        buffer_.erase(index);
        return 0;
      }
    }
  }
  std::lock_guard<std::mutex> lock(customers_file_mut_);
  std::string line;
  std::ifstream in_file(customers_file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    std::string username = GetRecordUsername(line_view);

    if (username == target_username &&
        !IsInvalidCustomer(GetRecordId(line_view))) {
      std::cout << "Deleting client with username: " << username << "\n";
      InvalidateCustomer(line_view);
      return 0;
    }
  }

  return -1;
}

void Database::InvalidateCustomer(std::string_view line_view) {
  std::lock_guard<std::mutex> lock(invalid_customers_file_mut_);
  std::ofstream invalid_file(invalid_customers_file_path_.c_str(),
                             std::ios::app);
  invalid_file << GetRecordId(line_view) << "\n";
}

bool Database::IsInvalidCustomer(uint64_t target_id) {
  std::lock_guard<std::mutex> lock(invalid_customers_file_mut_);
  std::string line;
  std::ifstream invalid_file(invalid_customers_file_path_.c_str(),
                             std::ios::in);
  while (std::getline(invalid_file, line)) {
    std::string_view line_view = line;
    uint64_t customer_id = std::stoull(std::string(line_view));
    if (customer_id == target_id) {
      return true;
    }
  }
  return false;
}

int Database::FlushToFile() {
  std::lock_guard<std::mutex> lock(customers_file_mut_);
  std::ofstream out_file(customers_file_path_.c_str(),
                         std::ios::out | std::ios::app);
  if (!out_file.is_open()) {
    return -1;
  }

  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[key, value] : buffer_) {
      out_file << "\t" << CustomerRecord(key, value).to_json() << "\n";
    }
    out_file.close();

    buffer_.clear();
  }
  return 0;
}
