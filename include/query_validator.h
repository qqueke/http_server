// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_QUERY_VALIDATOR_H_
#define INCLUDE_QUERY_VALIDATOR_H_

#include <optional>
#include <string>

class ITableQueryValidator {
 public:
  virtual std::optional<std::string> ValidateQuery(const std::string &operation,
                                                   const std::string &data) = 0;
};

#endif  // INCLUDE_QUERY_VALIDATOR_H_
