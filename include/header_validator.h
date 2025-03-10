#ifndef HEADER_VALIDATOR_HPP
#define HEADER_VALIDATOR_HPP

#include <string>
#include <unordered_map>

class IHeaderValidator {
public:
  virtual void ValidateHeaders(std::string &headers) = 0;

  virtual void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) = 0;
};

class RequestHeaderValidator : public IHeaderValidator {
public:
  void ValidateHeaders(std::string &headers) override;

  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

class ResponseHeaderValidator : public IHeaderValidator {
public:
  void ValidateHeaders(std::string &headers) override;

  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &pseudo_headers) override;
};

#endif
