#ifndef INCLUDE_CUSTOMERS_TABLE_H_
#define INCLUDE_CUSTOMERS_TABLE_H_

#include <cstdint>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

#include "database_tables.h"

struct Customer {
  std::string username;
  std::string customer_name;

  Customer() = default;

  Customer(const std::string &username, const std::string &customer_name)
      : username(username), customer_name(customer_name) {}

  std::string to_json() const {
    std::stringstream ss;
    ss << "{ ";
    ss << "\"username\": \"" << username << "\", ";
    ss << "\"customer_name\": \"" << customer_name << "\"";
    ss << " }";
    return ss.str();
  }
};

struct CustomerRecord {
  uint64_t customer_id;
  Customer &customer;
  uint8_t invalidated;

  CustomerRecord(uint64_t customer_id, Customer &customer,
                 uint8_t invalidated = 0)
      : customer_id(customer_id),
        customer(customer),
        invalidated(invalidated) {}

  CustomerRecord(uint64_t customer_id, Customer &&customer,
                 uint8_t invalidated = 0)
      : customer_id(customer_id),
        customer(customer),
        invalidated(invalidated) {}

  std::string to_json() const {
    std::stringstream ss;
    ss << "{ ";
    ss << "\"customer_id\": " << customer_id << ", ";
    ss << "\"username\": \"" << customer.username << "\", ";
    ss << "\"customer_name\": \"" << customer.customer_name << "\", ";
    ss << "\"invalid\": \"" << static_cast<int>(invalidated) << "\"";
    ss << " }";
    return ss.str();
  }
};

class CustomersTable : public ITable {
 public:
  CustomersTable();
  ~CustomersTable() override;

  int Add(const std::string &data) override;

  int Delete(const std::string &data) override;

  std::optional<std::string> Search(const std::string &data) override;

  std::string GetDeleteKeyFromAddData(const std::string &data) override;

  std::optional<std::string> GetAddDataFromDeleteKey(
      const std::string &data) override;

 private:
  uint64_t table_idx_;

  std::unordered_map<uint64_t, Customer> buffer_;
  // std::mutex buffer_mut_;

  std::string file_path_;
  // std::mutex file_mut_;

  void FlushToFile();

  uint64_t GetRecordId(std::string_view line);

  std::string GetRecordUsername(std::string_view line);

  bool IsInvalidCustomer(std::string_view line_view);

  Customer DeserializeCustomer(std::string_view line);

  void InitializeIndexFromFile();
};
#endif  // INCLUDE_CUSTOMERS_TABLE_H_
