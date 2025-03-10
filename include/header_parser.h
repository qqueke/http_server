// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file header_parser.h
 * @brief Header parsing and validation interface and implementations.
 *
 * This file provides the interface `IHeaderParser` and its implementations for
 * parsing and validating HTTP request and response headers. It includes methods
 * for converting headers to pseudo-headers, validating headers, and managing
 * pseudo-header integrity.
 */
#ifndef INCLUDE_HEADER_PARSER_H_
#define INCLUDE_HEADER_PARSER_H_

#include <memory>
#include <string>
#include <unordered_map>

#include "header_validator.h"

/**
 * @interface IHeaderParser
 * @brief Interface for header parsing and validation.
 *
 * This interface defines the methods required for converting headers to
 * pseudo-headers, validating headers, and validating pseudo-headers. It is
 * implemented by classes that handle HTTP request and response headers.
 */
class IHeaderParser {
 public:
  /**
   * @brief Converts headers to pseudo-headers.
   *
   * This method parses HTTP headers and converts them into pseudo-headers.
   *
   * @param headers A string view representing the headers to convert.
   * @return A map of pseudo-headers, where the keys are header names and values
   * are header values.
   */
  virtual std::unordered_map<std::string, std::string> ConvertToPseudoHeaders(
      const std::string_view headers) = 0;

  /**
   * @brief Validates HTTP headers.
   *
   * This method validates the given HTTP headers to ensure their correctness.
   *
   * @param headers The headers to validate.
   */
  virtual void ValidateHeaders(std::string &headers) = 0;

  /**
   * @brief Validates pseudo-headers.
   *
   * This method validates the given pseudo-headers.
   *
   * @param pseudo_headers A map of pseudo-headers to validate.
   */
  virtual void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) = 0;
};

/**
 * @class RequestHeaderParser
 * @brief Parses and validates HTTP request headers.
 *
 * This class implements the `IHeaderParser` interface for processing HTTP
 * request headers. It converts request headers to pseudo-headers, validates
 * request headers, and validates the associated pseudo-headers.
 */
class RequestHeaderParser : public IHeaderParser {
 private:
  RequestHeaderValidator validator_; /**< Validator for request headers. */

 public:
  /**
   * @brief Converts request headers to pseudo-headers.
   *
   * This method parses request headers and converts them into pseudo-headers.
   *
   * @param headers A string view representing the request headers to convert.
   * @return A map of pseudo-headers.
   */
  std::unordered_map<std::string, std::string> ConvertToPseudoHeaders(
      const std::string_view headers) override;

  /**
   * @brief Validates request headers.
   *
   * This method validates the given HTTP request headers.
   *
   * @param headers The request headers to validate.
   */
  void ValidateHeaders(std::string &headers) override;

  /**
   * @brief Validates request pseudo-headers.
   *
   * This method validates the given pseudo-headers for HTTP requests.
   *
   * @param pseudo_headers A map of pseudo-headers to validate.
   */
  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

/**
 * @class ResponseHeaderParser
 * @brief Parses and validates HTTP response headers.
 *
 * This class implements the `IHeaderParser` interface for processing HTTP
 * response headers. It converts response headers to pseudo-headers, validates
 * response headers, and validates the associated pseudo-headers.
 */
class ResponseHeaderParser : public IHeaderParser {
 private:
  ResponseHeaderValidator validator_; /**< Validator for response headers. */

 public:
  /**
   * @brief Converts response headers to pseudo-headers.
   *
   * This method parses response headers and converts them into pseudo-headers.
   *
   * @param headers A string view representing the response headers to convert.
   * @return A map of pseudo-headers.
   */
  std::unordered_map<std::string, std::string> ConvertToPseudoHeaders(
      const std::string_view headers) override;

  /**
   * @brief Validates response headers.
   *
   * This method validates the given HTTP response headers.
   *
   * @param headers The response headers to validate.
   */
  void ValidateHeaders(std::string &headers) override;

  /**
   * @brief Validates response pseudo-headers.
   *
   * This method validates the given pseudo-headers for HTTP responses.
   *
   * @param pseudo_headers A map of pseudo-headers to validate.
   */
  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

/**
 * @class HeaderParser
 * @brief A utility class to parse and validate HTTP headers and pseudo-headers.
 *
 * The `HeaderParser` class provides methods to validate both request and
 * response headers, as well as convert them to pseudo-headers. It utilizes
 * `RequestHeaderParser` and `ResponseHeaderParser` to handle the specific
 * parsing and validation logic for each type of header.
 */
class HeaderParser {
 private:
  ResponseHeaderParser res_parser_; /**< The response header parser. */
  RequestHeaderParser req_parser_;  /**< The request header parser. */

 public:
  /**
   * @brief Validates HTTP request headers.
   *
   * This method validates the provided request headers.
   *
   * @param headers The request headers to validate.
   */
  void ValidateRequestHeaders(std::string &headers);

  /**
   * @brief Validates HTTP response headers.
   *
   * This method validates the provided response headers.
   *
   * @param headers The response headers to validate.
   */
  void ValidateResponseHeaders(std::string &headers);

  /**
   * @brief Validates request pseudo-headers.
   *
   * This method validates the provided pseudo-headers for HTTP requests.
   *
   * @param pseudo_headers The request pseudo-headers to validate.
   */
  void ValidateRequestPseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers);

  /**
   * @brief Validates response pseudo-headers.
   *
   * This method validates the provided pseudo-headers for HTTP responses.
   *
   * @param pseudo_headers The response pseudo-headers to validate.
   */
  void ValidateResponsePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers);

  /**
   * @brief Converts request headers to pseudo-headers.
   *
   * This method converts HTTP request headers to pseudo-headers.
   *
   * @param headers A string view representing the request headers.
   * @return A map of pseudo-headers.
   */
  std::unordered_map<std::string, std::string> ConvertRequestToPseudoHeaders(
      std::string_view headers);

  /**
   * @brief Converts response headers to pseudo-headers.
   *
   * This method converts HTTP response headers to pseudo-headers.
   *
   * @param headers A string view representing the response headers.
   * @return A map of pseudo-headers.
   */
  std::unordered_map<std::string, std::string> ConvertResponseToPseudoHeaders(
      std::string_view headers);
};

#endif  // INCLUDE_HEADER_PARSER_H_
