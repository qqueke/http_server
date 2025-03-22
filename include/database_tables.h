// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file database_tables.h
 * @brief Defines the ITable interface and TableOp enumeration for database
 * table operations.
 *
 * This file declares the `ITable` interface, which is the base class for all
 * database table classes. It also defines the `TableOp` enumeration, which
 * specifies different types of operations that can be performed on a database
 * table, such as ADD, DELETE, and SEARCH.
 */

#ifndef INCLUDE_DATABASE_TABLES_H_
#define INCLUDE_DATABASE_TABLES_H_

#include <cstdint>
#include <optional>
#include <string>

/**
 * @enum TableOp
 * @brief Specifies the types of operations that can be performed on a database
 * table.
 *
 * This enum defines the different operations supported by the database:
 * - `ADD`: Insert a new record.
 * - `DELETE`: Remove a record.
 * - `SEARCH`: Look up a record based on a key.
 */
enum TableOp : uint8_t {
  ADD = 0,     ///< Add a new record to the table
  DELETE = 1,  ///< Delete an existing record from the table
  SEARCH = 2,  ///< Search for a record in the table
};

/**
 * @class ITable
 * @brief Interface for interacting with database tables.
 *
 * The `ITable` class defines the basic operations that all database tables
 * should support. These operations include adding, deleting, searching for
 * records, and obtaining data necessary for key operations.
 */
class ITable {
 public:
  /**
   * @brief Virtual destructor for ITable class.
   *
   * Ensures proper cleanup of derived classes when the base class pointer is
   * used.
   */
  virtual ~ITable() = default;

  /**
   * @brief Adds data to the database table.
   *
   * This method inserts a new record into the table.
   *
   * @param data The data to be added, typically in JSON format.
   * @return An integer indicating the success (0) or failure (non-zero) of the
   * operation.
   */
  virtual int Add(const std::string &data) = 0;

  /**
   * @brief Deletes data from the database table.
   *
   * This method removes an existing record from the table.
   *
   * @param data The data to be deleted, typically in JSON format.
   * @return An integer indicating the success (0) or failure (non-zero) of the
   * operation.
   */
  virtual int Delete(const std::string &data) = 0;

  /**
   * @brief Searches for data in the database table.
   *
   * This method looks up a record in the table based on the provided search
   * criteria.
   *
   * @param data The search criteria, typically in JSON format.
   * @return An optional string containing the search result if found;
   * otherwise, an empty optional.
   */
  virtual std::optional<std::string> Search(const std::string &data) = 0;

  /**
   * @brief Retrieves the delete key from the added data.
   *
   * This method extracts the delete key from the provided data, which is
   * typically used for identifying which record should be removed.
   *
   * @param data The data used to extract the delete key.
   * @return A string representing the delete key.
   */
  virtual std::string GetDeleteKeyFromAddData(const std::string &data) = 0;

  /**
   * @brief Retrieves the data to add based on the delete key.
   *
   * This method extracts the data to be added back to the table, given a delete
   * key.
   *
   * @param data The delete key.
   * @return An optional string containing the data to be added if found;
   * otherwise, an empty optional.
   */
  virtual std::optional<std::string> GetAddDataFromDeleteKey(
      const std::string &data) = 0;

 private:
  /**
   * @brief Flushes the data to the file.
   *
   * This private method handles flushing the current data state to the
   * underlying file to ensure persistence.
   */
  void FlushToFile();
};

#endif  // INCLUDE_DATABASE_TABLES_H_
