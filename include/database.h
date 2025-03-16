// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_DATABASE_H
#define INCLUDE_DATABASE_H
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

struct Customer {
  std::string username;
  std::string customer_name;

  Customer() = default;

  Customer(const std::string &username, const std::string &customer_name)
      : username(username), customer_name(customer_name) {}
};

struct CustomerRecord {
  uint64_t customer_id;
  Customer &customer;

  CustomerRecord(uint64_t customer_id, Customer &customer)
      : customer_id(customer_id), customer(customer) {}

  std::string to_json() const {
    std::stringstream ss;
    ss << "{ ";
    ss << "\"customer_id\": " << customer_id << ", ";
    ss << "\"username\": \"" << customer.username << "\", ";
    ss << "\"customer_name\": \"" << customer.customer_name << "\"";
    ss << " }";
    return ss.str();
  }
};

class Database {
 public:
  ~Database();

  Database(const Database &) = delete;

  Database &operator=(const Database &) = delete;

  static std::shared_ptr<Database> GetInstance();

  int RegisterCustomer(const Customer &customer);

  std::optional<Customer> Search4Customer(uint64_t target_id);

  int DeleteCustomer(const uint64_t customer_id);

  std::optional<Customer> Search4Customer(const std::string &target_username);

  int DeleteCustomer(const std::string &username);

  Customer DeserializeCustomer(std::string_view line);

  int FlushToFile();

 private:
  Database();

  static std::weak_ptr<Database> instance_;

  uint64_t curr_idx_;

  static std::mutex instance_mut_;

  std::mutex buffer_mut_;

  std::mutex customers_file_mut_;

  std::mutex invalid_customers_file_mut_;

  std::unordered_map<uint64_t, Customer> buffer_;

  std::string customers_file_path_;

  std::string invalid_customers_file_path_;

  uint64_t GetRecordId(std::string_view line);

  std::string GetRecordUsername(std::string_view line);

  bool IsInvalidCustomer(uint64_t target_id);

  void InvalidateCustomer(std::string_view line_view);

  void InitializeIndexFromFile();
};

#endif  // INCLUDE_DATABASE_H
