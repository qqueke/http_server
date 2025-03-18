#include "../include/database_tables.h"

#include <fstream>
#include <iostream>
#include <optional>

int CustomersTable::Add(const std::string &data) {
  // ParseData(data);

  Customer customer(data, "random");

  if (Search(customer.username) != std::nullopt) {
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
    buffer_.emplace(table_idx_, customer);
  }

  FlushToFile();

  // if (buffer_.size() >= 10) {
  //   FlushToFile();
  // }
  return 0;
}

int CustomersTable::Delete(const std::string &data) {
  const std::string &target_username = data;
  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[index, customer] : buffer_) {
      if (customer.username == target_username) {
        buffer_.erase(index);
        return 0;
      }
    }
  }
  std::lock_guard<std::mutex> lock(file_mut_);
  std::string line;
  std::ifstream in_file(file_path_.c_str(), std::ios::in);

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

std::optional<std::string> CustomersTable::Search(const std::string &data) {
  // If still in memory, perfect
  const std::string &target_username = data;
  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[index, customer] : buffer_) {
      if (customer.username == target_username) {
        return CustomerRecord(index, customer).to_json();
      }
    }
  }

  std::lock_guard<std::mutex> lock(file_mut_);
  std::string line;
  std::ifstream in_file(file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    std::string username = GetRecordUsername(line_view);

    if (username == target_username &&
        !IsInvalidCustomer(GetRecordId(line_view))) {
      return CustomerRecord(GetRecordId(line_view),
                            DeserializeCustomer(line_view))
          .to_json();
    }
  }

  return std::nullopt;
}

void CustomersTable::FlushToFile() {
  std::lock_guard<std::mutex> lock(file_mut_);
  std::ofstream out_file(file_path_.c_str(), std::ios::out | std::ios::app);
  if (!out_file.is_open()) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[key, value] : buffer_) {
      out_file << "\t" << CustomerRecord(key, value).to_json() << "\n";
    }
    out_file.close();

    buffer_.clear();
  }
}

std::string CustomersTable::GetRecordUsername(std::string_view line) {
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

uint64_t CustomersTable::GetRecordId(std::string_view line) {
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

bool CustomersTable::IsInvalidCustomer(uint64_t target_id) {
  std::lock_guard<std::mutex> lock(invalid_file_mut_);
  std::string line;
  std::ifstream invalid_file(invalid_file_path_.c_str(), std::ios::in);
  while (std::getline(invalid_file, line)) {
    std::string_view line_view = line;
    uint64_t customer_id = std::stoull(std::string(line_view));
    if (customer_id == target_id) {
      return true;
    }
  }
  return false;
}

void CustomersTable::InvalidateCustomer(std::string_view line_view) {
  std::lock_guard<std::mutex> lock(invalid_file_mut_);
  std::ofstream invalid_file(invalid_file_path_.c_str(), std::ios::app);
  invalid_file << GetRecordId(line_view) << "\n";
}

Customer CustomersTable::DeserializeCustomer(std::string_view line) {
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

void CustomersTable::InitializeIndexFromFile() {
  std::string line;
  std::ifstream in_file(file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    uint64_t id = GetRecordId(line_view);
    table_idx_ = (id > table_idx_) ? id + 1 : table_idx_ + 1;
  }
  std::cout << "Acquired idx:" << table_idx_ << '\n';
}

CustomersTable::~CustomersTable() {
  std::cout << "Destructed customers table\n";
  // Flush buffer to file
}

CustomersTable::CustomersTable() : table_idx_(0) {
  std::cout << "Creating customers table\n";
  const char *db_file_path = getenv("DATABASE");
  if (db_file_path != nullptr) {
    file_path_ = std::string(db_file_path);
  } else {
    file_path_ = "db.json";
  }

  const char *invalid_file_path = getenv("INVALID");
  if (invalid_file_path != nullptr) {
    invalid_file_path_ = std::string(invalid_file_path);
  } else {
    invalid_file_path_ = "invalid.json";
  }
  InitializeIndexFromFile();
}
