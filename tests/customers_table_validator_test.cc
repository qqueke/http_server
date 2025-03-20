
#include "../include/customers_table_validator.h"

#include <gtest/gtest.h>

class CustomersTableValidatorTest : public ::testing::Test {
 protected:
  CustomersTableValidator validator;
};

TEST_F(CustomersTableValidatorTest, ValidateAdd_ValidData) {
  std::string valid_json =
      "{\"username\":\"user123\",\"customer_name\":\"John Doe\"}";
  EXPECT_FALSE(validator.ValidateAdd(valid_json).has_value());
}

TEST_F(CustomersTableValidatorTest, ValidateAdd_InvalidJsonFormat) {
  std::string invalid_json = "username:\"user123\",customer_name:\"John Doe\"";
  EXPECT_EQ(validator.ValidateAdd(invalid_json).value(),
            "Invalid JSON format.");
}

TEST_F(CustomersTableValidatorTest, ValidateAdd_MissingUsername) {
  std::string json_missing_username = "{\"customer_name\":\"John Doe\"}";
  EXPECT_EQ(validator.ValidateAdd(json_missing_username).value(),
            "'username' field is missing.");
}

TEST_F(CustomersTableValidatorTest, ValidateAdd_MissingCustomerName) {
  std::string json_missing_customer_name = "{\"username\":\"user123\"}";
  EXPECT_EQ(validator.ValidateAdd(json_missing_customer_name).value(),
            "'customer_name' field is missing.");
}

TEST_F(CustomersTableValidatorTest, ValidateDelete_ValidData) {
  std::string valid_json = "{\"username\":\"user123\"}";
  EXPECT_FALSE(validator.ValidateDelete(valid_json).has_value());
}

TEST_F(CustomersTableValidatorTest, ValidateDelete_MissingUsername) {
  std::string json_missing_username = "{}";
  EXPECT_EQ(validator.ValidateDelete(json_missing_username).value(),
            "'username' field is missing.");
}

TEST_F(CustomersTableValidatorTest, ValidateSearch_ValidData) {
  std::string valid_json = "{\"username\":\"user123\"}";
  EXPECT_FALSE(validator.ValidateSearch(valid_json).has_value());
}

TEST_F(CustomersTableValidatorTest, ValidateSearch_MissingUsername) {
  std::string json_missing_username = "{}";
  EXPECT_EQ(validator.ValidateSearch(json_missing_username).value(),
            "'username' field is missing.");
}

TEST_F(CustomersTableValidatorTest, ValidateQuery_UnknownOperation) {
  std::string valid_json =
      "{\"username\":\"user123\",\"customer_name\":\"John Doe\"}";
  EXPECT_EQ(validator.ValidateQuery("UPDATE", valid_json).value(),
            "Unknown operation");
}

TEST_F(CustomersTableValidatorTest, ValidateQuery_MissingFormatting) {
  std::string invalid_json =
      "{\"username\":\"user123,\"customer_name\":\"John Doe\"}";
  EXPECT_EQ(validator.ValidateAdd(invalid_json).value(),
            "'customer_name' field is missing.");
}
