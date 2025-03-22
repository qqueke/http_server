// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file customers_table.h
 * @brief Defines the CustomersTable class and related structures for managing
 * customer records.
 *
 * This file declares the `CustomersTable` class, which implements an in-memory
 * and file-backed storage system for customer data. It provides functionalities
 * to add, delete, and search for customer records.
 */

#ifndef INCLUDE_CUSTOMERS_TABLE_H_
#define INCLUDE_CUSTOMERS_TABLE_H_

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

#include "../include/database_tables.h"

/**
 * @struct Customer
 * @brief Represents a customer with a username and a customer name.
 */
struct Customer {
  std::string username;       ///< The username of the customer.
  std::string customer_name;  ///< The full name of the customer.

  /**
   * @brief Default constructor.
   */
  Customer() = default;

  /**
   * @brief Parameterized constructor.
   * @param username The customer's username.
   * @param customer_name The full name of the customer.
   */
  Customer(const std::string &username, const std::string &customer_name)
      : username(username), customer_name(customer_name) {}

  /**
   * @brief Serializes the customer data to a JSON string.
   * @return A JSON-formatted string representing the customer.
   */
  std::string to_json() const {
    std::stringstream ss;
    ss << "{ ";
    ss << "\"username\": \"" << username << "\", ";
    ss << "\"customer_name\": \"" << customer_name << "\"";
    ss << " }";
    return ss.str();
  }
};

/**
 * @struct CustomerRecord
 * @brief Represents a customer record with an ID, customer data, and an
 * invalidation flag.
 */
struct CustomerRecord {
  uint64_t customer_id;  ///< The unique identifier for the customer.
  Customer &customer;    ///< Reference to the associated customer data.
  uint8_t invalidated;   ///< Flag indicating whether the record is invalid (0 =
                         ///< valid, 1 = invalid).

  /**
   * @brief Constructor for a customer record.
   * @param customer_id The unique customer ID.
   * @param customer Reference to a Customer object.
   * @param invalidated Flag indicating if the record is invalid (default is 0).
   */
  CustomerRecord(uint64_t customer_id, Customer &customer,
                 uint8_t invalidated = 0)
      : customer_id(customer_id),
        customer(customer),
        invalidated(invalidated) {}

  /**
   * @brief Constructor for a customer record with an rvalue reference.
   * @param customer_id The unique customer ID.
   * @param customer Rvalue reference to a Customer object.
   * @param invalidated Flag indicating if the record is invalid (default is 0).
   */
  CustomerRecord(uint64_t customer_id, Customer &&customer,
                 uint8_t invalidated = 0)
      : customer_id(customer_id),
        customer(customer),
        invalidated(invalidated) {}

  /**
   * @brief Serializes the customer record to a JSON string.
   * @return A JSON-formatted string representing the customer record.
   */
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

/**
 * @class CustomersTable
 * @brief Manages customer records, providing functions for adding, deleting,
 * and searching.
 *
 * The `CustomersTable` class implements an in-memory database for customer
 * records and supports file persistence. It inherits from `ITable`, defining
 * the required database operations.
 */
class CustomersTable : public ITable {
 public:
  /**
   * @brief Constructs a CustomersTable instance.
   */
  CustomersTable();

  /**
   * @brief Destroys the CustomersTable instance.
   */
  ~CustomersTable() override;

  /**
   * @brief Adds a new customer record.
   * @param data JSON-formatted customer data.
   * @return 0 on success, non-zero on failure.
   */
  int Add(const std::string &data) override;

  /**
   * @brief Deletes a customer record.
   * @param data JSON-formatted customer data containing the key to delete.
   * @return 0 on success, non-zero on failure.
   */
  int Delete(const std::string &data) override;

  /**
   * @brief Searches for a customer record.
   * @param data JSON-formatted search criteria.
   * @return The customer data as a JSON string if found, otherwise an empty
   * optional.
   */
  std::optional<std::string> Search(const std::string &data) override;

  /**
   * @brief Extracts the delete key from add data.
   * @param data JSON-formatted customer data.
   * @return A key used for deleting the record.
   */
  std::string GetDeleteKeyFromAddData(const std::string &data) override;

  /**
   * @brief Extracts the add data from a delete key.
   * @param data JSON-formatted delete key.
   * @return JSON-formatted add data if available, otherwise an empty optional.
   */
  std::optional<std::string> GetAddDataFromDeleteKey(
      const std::string &data) override;

 private:
  uint64_t table_idx_;  ///< The index for new customer records.

  std::unordered_map<uint64_t, Customer>
      buffer_;  ///< In-memory customer record storage.

  std::string file_path_;  ///< File path for persisting customer records.

  /**
   * @brief Writes buffered customer records to a file.
   */
  void FlushToFile();

  /**
   * @brief Extracts the customer ID from a file record.
   * @param line A line of data from the file.
   * @return The extracted customer ID.
   */
  uint64_t GetRecordId(std::string_view line);

  /**
   * @brief Extracts the username from a file record.
   * @param line A line of data from the file.
   * @return The extracted username.
   */
  std::string GetRecordUsername(std::string_view line);

  /**
   * @brief Checks if a customer record is invalid.
   * @param line_view A line of data from the file.
   * @return True if the record is invalid, otherwise false.
   */
  bool IsInvalidCustomer(std::string_view line_view);

  /**
   * @brief Deserializes a customer from a file record.
   * @param line A line of data from the file.
   * @return A Customer object parsed from the file record.
   */
  Customer DeserializeCustomer(std::string_view line);

  /**
   * @brief Initializes the table index by reading from the file.
   */
  void InitializeIndexFromFile();
};

#endif  // INCLUDE_CUSTOMERS_TABLE_H_
