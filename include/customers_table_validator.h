#ifndef INCLUDE_CUSTOMERS_TABLE_VALIDATOR_H_
#define INCLUDE_CUSTOMERS_TABLE_VALIDATOR_H_

#include <optional>
#include <string>

#include "query_validator.h"

class CustomersTableValidator : public ITableQueryValidator {
 public:
  std::optional<std::string> ValidateQuery(const std::string &operation,
                                           const std::string &data) override;

  std::optional<std::string> ValidateAdd(const std::string &data);

  std::optional<std::string> ValidateDelete(const std::string &data);

  std::optional<std::string> ValidateSearch(const std::string &data);

 private:
};

#endif  // INCLUDE_CUSTOMERS_TABLE_VALIDATOR_H_
