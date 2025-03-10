#ifndef HEADER_PARSER_HPP
#define HEADER_PARSER_HPP

#include <memory>
#include <string>
#include <unordered_map>

#include "header_validator.h"

class IHeaderParser {
public:
  virtual std::unordered_map<std::string, std::string>
  ConvertToPseudoHeaders(const std::string_view headers) = 0;

  virtual void ValidateHeaders(std::string &headers) = 0;

  virtual void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) = 0;
};

class RequestHeaderParser : public IHeaderParser {
private:
  RequestHeaderValidator validator_;

public:
  std::unordered_map<std::string, std::string>
  ConvertToPseudoHeaders(const std::string_view headers) override;

  void ValidateHeaders(std::string &headers) override;

  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

// Response-specific header processor
class ResponseHeaderParser : public IHeaderParser {
private:
  ResponseHeaderValidator validator_;

public:
  std::unordered_map<std::string, std::string>
  ConvertToPseudoHeaders(const std::string_view headers) override;

  void ValidateHeaders(std::string &headers) override;

  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

class HeaderParser {
private:
  ResponseHeaderParser res_parser_;
  RequestHeaderParser req_parser_;

public:
  // Validate request headers
  void ValidateRequestHeaders(std::string &headers);

  // Validate response headers
  void ValidateResponseHeaders(std::string &headers);

  // Validate request pseudo-headers
  void ValidateRequestPseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers);

  // Validate response pseudo-headers
  void ValidateResponsePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers);

  // Convert request headers to pseudo headers
  std::unordered_map<std::string, std::string>
  ConvertRequestToPseudoHeaders(std::string_view headers);

  // Convert response headers to pseudo headers
  std::unordered_map<std::string, std::string>
  ConvertResponseToPseudoHeaders(std::string_view headers);
};

#endif // HEADER_PARSER_HPP
