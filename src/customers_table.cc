// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/customers_table.h"

#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

int CustomersTable::Add(const std::string &data) {
  constexpr std::string_view username_field = "\"username\"";

  // Find "username" key and extract its value
  size_t username_pos = data.find(username_field);

  size_t username_value_start =
      data.find('"', username_pos + username_field.size() + 1);

  size_t username_value_end = data.find('"', username_value_start + 1);

  std::string username = data.substr(
      username_value_start + 1, username_value_end - username_value_start - 1);

  constexpr std::string_view customer_name_field = "\"customer_name\"";
  // Find "customer_name" key and extract its value
  size_t customer_name_pos =
      data.find(customer_name_field, username_value_end + 1);

  size_t customer_name_value_start =
      data.find('"', customer_name_pos + customer_name_field.size());

  size_t customer_name_value_end =
      data.find('"', customer_name_value_start + 1);

  std::string customer_name =
      data.substr(customer_name_value_start + 1,
                  customer_name_value_end - customer_name_value_start - 1);

  Customer customer(username, customer_name);

  if (Search(customer.username) != std::nullopt) {
    return -1;
  }

  // std::lock_guard<std::mutex> lock_buf(buffer_mut_);
  for (auto &[index, buffer_customer] : buffer_) {
    if (buffer_customer.username == customer.username) {
      return -1;
    }
  }

  // std::lock_guard<std::mutex> lock_buf(buffer_mut_);
  buffer_.emplace(table_idx_, customer);
  ++table_idx_;
  FlushToFile();

  // if (buffer_.size() >= 10) {
  //   FlushToFile();
  // }
  return 0;
}

int CustomersTable::Delete(const std::string &data) {
  std::string target_username = GetRecordUsername(std::string_view(data));

  for (auto &[index, customer] : buffer_) {
    if (customer.username == target_username) {
      buffer_.erase(index);
      return 0;
    }
  }

  std::string line;
  std::fstream file(file_path_, std::ios::in | std::ios::out);
  std::streampos line_pos = file.tellg();
  while (std::getline(file, line)) {
    std::string_view line_view = line;
    std::string username = GetRecordUsername(line_view);

    if (username == target_username) {
      std::string_view invalid_field = "\"invalid\": \"0\"";
      size_t invalid_pos = line_view.find(invalid_field);
      if (invalid_pos == std::string::npos) {
        line_pos = file.tellg();
        continue;
      }

      line.replace(invalid_pos, invalid_field.size(), "\"invalid\": \"1\"");
      file.seekp(line_pos);
      file << line << '\n';
      return 0;
    }
    line_pos = file.tellg();
  }

  return -1;
}

std::optional<std::string> CustomersTable::GetAddDataFromDeleteKey(
    const std::string &data) {
  std::string target_username = GetRecordUsername(std::string_view(data));
  for (auto &[index, customer] : buffer_) {
    if (customer.username == target_username) {
      return customer.to_json();
    }
  }

  std::string line;
  std::ifstream in_file(file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    std::string username = GetRecordUsername(line_view);

    if (username == target_username && !IsInvalidCustomer(line_view)) {
      Customer customer = DeserializeCustomer(line_view);
      return customer.to_json();
    }
  }

  return std::nullopt;
}

std::string CustomersTable::GetDeleteKeyFromAddData(const std::string &data) {
  std::string target_username = GetRecordUsername(std::string_view(data));

  std::string username_json = "{ \"username\": \"" + target_username + "\" }";

  return username_json;
}

std::optional<std::string> CustomersTable::Search(const std::string &data) {
  std::string target_username = GetRecordUsername(std::string_view(data));
  // std::lock_guard<std::mutex> lock_buf(buffer_mut_);
  for (auto &[index, customer] : buffer_) {
    if (customer.username == target_username) {
      return CustomerRecord(index, customer).to_json();
    }
  }

  std::string line;
  std::ifstream in_file(file_path_.c_str(), std::ios::in);

  while (std::getline(in_file, line)) {
    std::string_view line_view = line;
    std::string username = GetRecordUsername(line_view);

    if (username == target_username && !IsInvalidCustomer(line_view)) {
      return std::string(line_view);
    }
  }

  return std::nullopt;
}

void CustomersTable::FlushToFile() {
  // std::lock_guard<std::mutex> lock(file_mut_);
  std::ofstream out_file(file_path_.c_str(), std::ios::out | std::ios::app);
  if (!out_file.is_open()) {
    return;
  }

  {
    // std::lock_guard<std::mutex> lock_buf(buffer_mut_);
    for (auto &[key, value] : buffer_) {
      out_file << "\t" << CustomerRecord(key, value).to_json() << "\n";
    }
    out_file.close();

    buffer_.clear();
  }
}

std::string CustomersTable::GetRecordUsername(std::string_view line) {
  // Pass the field string by argument instead
  constexpr std::string_view username_field = "\"username\"";

  // Find "username" key and extract its value
  size_t username_pos = line.find(username_field);

  size_t username_value_start =
      line.find('"', username_pos + username_field.size() + 1);

  size_t username_value_end = line.find('"', username_value_start + 1);

  std::string target_username = std::string(line.substr(
      username_value_start + 1, username_value_end - username_value_start - 1));

  return target_username;
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

bool CustomersTable::IsInvalidCustomer(std::string_view line_view) {
  std::string_view invalid_field = "\"invalid\": \"1\"";
  size_t invalid_pos = line_view.find(invalid_field);
  if (invalid_pos == std::string::npos) {
    return false;
  }

  return true;
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

  InitializeIndexFromFile();
}
