
#include "../include/static_content_handler.h"

#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "../include/utils.h"

// Define the file paths for testing
const std::string test_input_file = "test_input.txt";
const std::string test_output_file_gzip = "test_output.gz";
const std::string test_output_file_deflate = "test_output.deflate";

// Helper function to create a test file with content
void CreateTestFile(const std::string &file_path, const std::string &content) {
  std::ofstream out(file_path);
  out << content;
  out.close();
}

// Helper function to delete the test file
void DeleteTestFile(const std::string &file_path) {
  (void)std::remove(file_path.c_str());
}

TEST(CompressionTest, CompressFileTmpGzip) {
  // Prepare the test input file
  CreateTestFile(test_input_file, "This is a test input for gzip compression.");

  // Call the function with GZIP compression type
  uint64_t compressed_size = StaticContentHandler::CompressFileTmp(
      test_input_file, test_output_file_gzip.c_str(), GZIP);

  // Check if the output file exists and has a size (i.e., it was compressed)
  std::ifstream out_file(test_output_file_gzip, std::ios::binary);
  ASSERT_TRUE(out_file.is_open()) << "Failed to open output gzip file.";
  ASSERT_GT(compressed_size, 0)
      << "Compressed file size should be greater than 0.";
  out_file.close();

  // Clean up the created files
  DeleteTestFile(test_input_file);
  DeleteTestFile(test_output_file_gzip);
}

TEST(CompressionTest, CompressFileTmpDeflate) {
  // Prepare the test input file
  CreateTestFile(test_input_file,
                 "This is a test input for deflate compression.");

  // Call the function with DEFLATE compression type
  uint64_t compressed_size = StaticContentHandler::CompressFileTmp(
      test_input_file, test_output_file_deflate.c_str(), DEFLATE);

  // Check if the output file exists and has a size (i.e., it was compressed)
  std::ifstream out_file(test_output_file_deflate, std::ios::binary);
  ASSERT_TRUE(out_file.is_open()) << "Failed to open output deflate file.";
  ASSERT_GT(compressed_size, 0)
      << "Compressed file size should be greater than 0.";
  out_file.close();

  // Clean up the created files
  DeleteTestFile(test_input_file);
  DeleteTestFile(test_output_file_deflate);
}

TEST(CompressionTest, CompressFileTmpFailsToOpenInputFile) {
  // Call the function with an invalid input file
  uint64_t compressed_size = StaticContentHandler::CompressFileTmp(
      "invalid_file.txt", test_output_file_gzip.c_str(), GZIP);
  ASSERT_EQ(compressed_size, 0)
      << "Compression should fail with invalid input file.";
}

TEST(CompressionTest, CompressFileTmpFailsToOpenOutputFile) {
  // Create the test input file
  CreateTestFile(test_input_file, "Test content.");

  // Try to compress to an invalid file (no permission)
  uint64_t compressed_size = StaticContentHandler::CompressFileTmp(
      test_input_file, "/invalid_path/test_output.gz", GZIP);
  ASSERT_EQ(compressed_size, 0)
      << "Compression should fail with invalid output file.";

  // Clean up the created test input file
  DeleteTestFile(test_input_file);
}
