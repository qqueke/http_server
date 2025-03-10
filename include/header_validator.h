// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file header_validator.h
 * @brief Interface and implementations for HTTP header validation.
 *
 * This file provides the interface `IHeaderValidator` and its implementations
 * for validating HTTP request and response headers. It includes methods for
 * validating headers and pseudo-headers.
 */
#ifndef INCLUDE_HEADER_VALIDATOR_H_
#define INCLUDE_HEADER_VALIDATOR_H_

#include <string>
#include <unordered_map>

/**
 * @interface IHeaderValidator
 * @brief Interface for validating HTTP headers and pseudo-headers.
 *
 * This interface defines the methods required for validating both HTTP headers
 * and pseudo-headers. It is implemented by classes that handle HTTP request and
 * response header validation.
 */
class IHeaderValidator {
 public:
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
   * This method validates the given pseudo-headers for HTTP requests or
   * responses.
   *
   * @param pseudo_headers A map of pseudo-headers to validate.
   */
  virtual void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) = 0;
};

/**
 * @class RequestHeaderValidator
 * @brief Validates HTTP request headers and pseudo-headers.
 *
 * This class implements the `IHeaderValidator` interface for validating HTTP
 * request headers and their associated pseudo-headers. It ensures the
 * correctness and format of request headers.
 */
class RequestHeaderValidator : public IHeaderValidator {
 public:
  /**
   * @brief Validates HTTP request headers.
   *
   * This method validates the given HTTP request headers to ensure their
   * correctness.
   *
   * @param headers The request headers to validate.
   */
  void ValidateHeaders(std::string &headers) override;

  /**
   * @brief Validates HTTP request pseudo-headers.
   *
   * This method validates the given pseudo-headers for HTTP requests.
   *
   * @param pseudo_headers A map of pseudo-headers to validate.
   */
  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

/**
 * @class ResponseHeaderValidator
 * @brief Validates HTTP response headers and pseudo-headers.
 *
 * This class implements the `IHeaderValidator` interface for validating HTTP
 * response headers and their associated pseudo-headers. It ensures the
 * correctness and format of response headers.
 */
class ResponseHeaderValidator : public IHeaderValidator {
 public:
  /**
   * @brief Validates HTTP response headers.
   *
   * This method validates the given HTTP response headers to ensure their
   * correctness.
   *
   * @param headers The response headers to validate.
   */
  void ValidateHeaders(std::string &headers) override;

  /**
   * @brief Validates HTTP response pseudo-headers.
   *
   * This method validates the given pseudo-headers for HTTP responses.
   *
   * @param pseudo_headers A map of pseudo-headers to validate.
   */
  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

#endif  // INCLUDE_HEADER_VALIDATOR_H_
