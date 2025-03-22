// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file customers_table_validator.h
 * @brief Defines the CustomersTableValidator class for validating customer
 * table queries.
 *
 * This file declares the `CustomersTableValidator` class, which provides query
 * validation for operations on the `CustomersTable`. It ensures that operations
 * such as adding, deleting, and searching for customers are performed with
 * valid data.
 */

#ifndef INCLUDE_CUSTOMERS_TABLE_VALIDATOR_H_
#define INCLUDE_CUSTOMERS_TABLE_VALIDATOR_H_

#include <optional>
#include <string>

#include "../include/query_validator.h"

/**
 * @class CustomersTableValidator
 * @brief Validates queries for operations on the CustomersTable.
 *
 * This class implements validation rules for queries related to customer
 * records. It ensures that `ADD`, `DELETE`, and `SEARCH` operations receive
 * properly formatted data.
 */
class CustomersTableValidator : public ITableQueryValidator {
 public:
  /**
   * @brief Validates a generic query based on the operation type and data.
   *
   * This function determines whether the given operation and its associated
   * data are valid. It delegates to more specific validation methods depending
   * on the operation type.
   *
   * @param operation The type of operation (e.g., "ADD", "DELETE", "SEARCH").
   * @param data JSON-formatted data associated with the operation.
   * @return An error message if validation fails, otherwise an empty optional.
   */
  std::optional<std::string> ValidateQuery(const std::string &operation,
                                           const std::string &data) override;

  /**
   * @brief Validates the input data for an ADD operation.
   *
   * Ensures that the data provided for adding a customer is properly formatted.
   *
   * @param data JSON-formatted customer data.
   * @return An error message if validation fails, otherwise an empty optional.
   */
  std::optional<std::string> ValidateAdd(const std::string &data);

  /**
   * @brief Validates the input data for a DELETE operation.
   *
   * Ensures that the required keys are present in the delete request.
   *
   * @param data JSON-formatted delete key.
   * @return An error message if validation fails, otherwise an empty optional.
   */
  std::optional<std::string> ValidateDelete(const std::string &data);

  /**
   * @brief Validates the input data for a SEARCH operation.
   *
   * Ensures that the search criteria is properly formatted.
   *
   * @param data JSON-formatted search criteria.
   * @return An error message if validation fails, otherwise an empty optional.
   */
  std::optional<std::string> ValidateSearch(const std::string &data);

 private:
  // Private members can be added here if needed in future implementations.
};

#endif  // INCLUDE_CUSTOMERS_TABLE_VALIDATOR_H_
