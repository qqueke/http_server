// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file query_validator.h
 * @brief Defines the interface for validating table-related queries.
 *
 * This file declares the `ITableQueryValidator` interface, which provides
 * a method for validating queries based on an operation type and associated
 * data. The validation method returns an optional string containing an error
 * message if the validation fails.
 *
 * @author Your Name
 * @date 2025-03-22
 */

#ifndef INCLUDE_QUERY_VALIDATOR_H_
#define INCLUDE_QUERY_VALIDATOR_H_

#include <optional>
#include <string>

/**
 * @class ITableQueryValidator
 * @brief Interface for validating table-related queries.
 *
 * This interface provides a method to validate queries based on
 * an operation type and associated data.
 */
class ITableQueryValidator {
 public:
  /**
   * @brief Validates a query based on the given operation and data.
   *
   * This function checks if the provided operation and data are valid.
   * If the validation fails, it returns an error message.
   *
   * @param operation The type of operation (e.g., "INSERT", "DELETE",
   * "UPDATE").
   * @param data The data associated with the operation.
   * @return std::optional<std::string> An error message if validation fails,
   *         otherwise an empty optional.
   */
  virtual std::optional<std::string> ValidateQuery(const std::string &operation,
                                                   const std::string &data) = 0;
};

#endif  // INCLUDE_QUERY_VALIDATOR_H_
