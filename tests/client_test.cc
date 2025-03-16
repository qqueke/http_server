#include "../include/client.h"

#include <gtest/gtest.h>

#include <fstream>

// Helper function to create a temporary test file
void WriteTestFile(const std::string &filename, const std::string &content) {
  std::ofstream file(filename);
  file << content;
  file.close();
}

// Test case for ParseRequestsFromFile
TEST(HttpClientTest, ParsesVariousRequestFiles) {
  int argc = 1;
  char *argv[] = {"test_client"};

  // Create HttpClient instance
  HttpClient client(argc, argv);

  // Define the file names and their respective contents for testing
  struct TestData {
    std::string filename;
    std::string content;
    std::string expected_header;
    std::string expected_body;
    size_t expected_size;
  };

  std::vector<TestData> test_cases = {
      // Valid request with body
      {.filename = "test_valid_request.txt",
       .content = "GET / HTTP/1.1\nHost: example.com\n\nBody: Hello, "
                  "world!\nAnother line "
                  "of body\n",
       .expected_header = "GET / HTTP/1.1\r\nHost: example.com\r\n",
       .expected_body = "Hello, world!\r\nAnother line of body",
       .expected_size = 1},
      // Request with no body
      {.filename = "test_no_body.txt",
       .content = "GET / HTTP/1.1\nHost: example.com\n\n",
       .expected_header = "GET / HTTP/1.1\r\nHost: example.com\r\n",
       .expected_body = "",
       .expected_size = 1},
      // Request with just the body and no headers
      {.filename = "test_no_header.txt",
       .content = "Body: Just the body text\nThis is all we have.\n",
       .expected_header = "",
       .expected_body = "Just the body text\r\nThis is all we have.",
       .expected_size = 0},
      // Request with malformed body
      {.filename = "test_malformed_body.txt",
       .content =
           "GET / HTTP/1.1\nHost: example.com\n\nBody: \nThis body line has a "
           "missing part\n",
       .expected_header = "GET / HTTP/1.1\r\nHost: example.com\r\n",
       .expected_body = "This body line has a missing part",
       .expected_size = 1},
  };

  // Loop through each test case
  for (const auto &test_case : test_cases) {
    // Write the test file
    WriteTestFile(test_case.filename, test_case.content);

    client.ParseRequestsFromFile(test_case.filename);

    // Check if the request was parsed correctly
    ASSERT_EQ(client.requests_.size(), test_case.expected_size);
    if (test_case.expected_size > 0) {
      EXPECT_EQ(client.requests_[0].first, test_case.expected_header);
      EXPECT_EQ(client.requests_[0].second, test_case.expected_body);
    }
    // Cleanup: remove the test file
    remove(test_case.filename.c_str());
    client.requests_.clear();
  }
}
