#ifndef INCLUDE_DATABASE_TABLES_H_
#define INCLUDE_DATABASE_TABLES_H_

#include <cstdint>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

enum TableOp : uint8_t {
  ADD = 0,
  DELETE = 1,
  SEARCH = 2,
};

class ITable {
 public:
  virtual ~ITable() = default;

  virtual int Add(const std::string &data) = 0;

  virtual int Delete(const std::string &data) = 0;

  // This function looks for indexing field
  virtual std::optional<std::string> Search(const std::string &data) = 0;

  // This function searches provided the same arguments to Add and returns
  // indexing field
  virtual std::optional<std::string> GetIndexFromEntry(
      const std::string &data) = 0;

  virtual std::string GetIndexFromAddData(const std::string &data) = 0;

  // This function looks for index and returns entry in same style as the input
  // to Add()
  virtual std::optional<std::string> GetEntryFromIndex(
      const std::string &data) = 0;

 private:
  void FlushToFile();
};

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

  CustomerRecord(uint64_t customer_id, Customer &&customer)
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

class CustomersTable : public ITable {
 public:
  CustomersTable();
  ~CustomersTable() override;

  int Add(const std::string &data) override;

  int Delete(const std::string &data) override;

  std::optional<std::string> Search(const std::string &data) override;

  std::optional<std::string> GetIndexFromEntry(
      const std::string &data) override;

  std::string GetIndexFromAddData(const std::string &data) override;

  std::optional<std::string> GetEntryFromIndex(
      const std::string &data) override;

 private:
  uint64_t table_idx_;

  std::unordered_map<uint64_t, Customer> buffer_;
  std::mutex buffer_mut_;

  std::string file_path_;
  std::mutex file_mut_;

  std::string invalid_file_path_;
  std::mutex invalid_file_mut_;

  void FlushToFile();

  uint64_t GetRecordId(std::string_view line);

  std::string GetRecordUsername(std::string_view line);

  bool IsInvalidCustomer(uint64_t target_id);

  void InvalidateCustomer(std::string_view line_view);

  Customer DeserializeCustomer(std::string_view line);

  void InitializeIndexFromFile();
};
#endif  // INCLUDE_DATABASE_TABLES_H_
