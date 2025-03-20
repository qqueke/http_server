#include "../include/customers_table_validator.h"

#include <optional>

std::optional<std::string> CustomersTableValidator::ValidateQuery(
    const std::string &operation, const std::string &data) {
  if (operation == "ADD") {
    return ValidateAdd(data);
  } else if (operation == "DELETE") {
    return ValidateDelete(data);
  } else if (operation == "SEARCH") {
    return ValidateSearch(data);
  } else {
    return "Unknown operation";
  }
}

std::optional<std::string> CustomersTableValidator::ValidateAdd(
    const std::string &data) {
  if (data.empty() || data.front() != '{' || data.back() != '}') {
    return "Invalid JSON format.";
  }

  constexpr std::string_view username_field = "\"username\"";

  // Find "username" key and extract its value
  size_t username_pos = data.find(username_field);
  if (username_pos == std::string::npos) {
    return "'username' field is missing.";
  }

  size_t username_value_start =
      data.find(':', username_pos + username_field.size());
  if (username_value_start == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  username_value_start = data.find('"', username_value_start + 1);
  if (username_value_start == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  size_t username_value_end = data.find('"', username_value_start + 1);
  if (username_value_end == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  constexpr std::string_view customer_name_field = "\"customer_name\"";
  // Find "customer_name" key and extract its value
  size_t customer_name_pos =
      data.find(customer_name_field, username_value_end + 1);
  if (customer_name_pos == std::string::npos) {
    return "'customer_name' field is missing.";
  }

  size_t customer_name_value_start =
      data.find(':', customer_name_pos + customer_name_field.size());
  if (customer_name_value_start == std::string::npos) {
    return "'customer_name' field has no assigned value.";
  }

  customer_name_value_start = data.find('"', customer_name_value_start + 1);
  if (customer_name_value_start == std::string::npos) {
    return "'customer_name' field has no assigned value.";
  }
  customer_name_value_start = data.find('"', customer_name_value_start + 1);
  if (customer_name_value_start == std::string::npos) {
    return "'customer_name' field has no assigned value.";
  }
  return std::nullopt;
}

std::optional<std::string> CustomersTableValidator::ValidateDelete(
    const std::string &data) {
  if (data.empty() || data.front() != '{' || data.back() != '}') {
    return "Invalid JSON format.";
  }

  constexpr std::string_view username_field = "\"username\"";

  // Find "username" key and extract its value
  size_t username_pos = data.find(username_field);
  if (username_pos == std::string::npos) {
    return "'username' field is missing.";
  }

  size_t username_value_start =
      data.find(':', username_pos + username_field.size());
  if (username_value_start == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  username_value_start = data.find('"', username_value_start + 1);
  if (username_value_start == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  size_t username_value_end = data.find('"', username_value_start + 1);
  if (username_value_end == std::string::npos) {
    return "'username' field has no assigned value.";
  }
  return std::nullopt;
}

std::optional<std::string> CustomersTableValidator::ValidateSearch(
    const std::string &data) {
  if (data.empty() || data.front() != '{' || data.back() != '}') {
    return "Invalid JSON format.";
  }

  constexpr std::string_view username_field = "\"username\"";

  // Find "username" key and extract its value
  size_t username_pos = data.find(username_field);
  if (username_pos == std::string::npos) {
    return "'username' field is missing.";
  }

  size_t username_value_start =
      data.find(':', username_pos + username_field.size());
  if (username_value_start == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  username_value_start = data.find('"', username_value_start + 1);
  if (username_value_start == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  size_t username_value_end = data.find('"', username_value_start + 1);
  if (username_value_end == std::string::npos) {
    return "'username' field has no assigned value.";
  }

  return std::nullopt;
}
