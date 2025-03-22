// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/header_validator.h"

#include <array>
#include <string>
#include <unordered_map>
// TODO(QQueke): Implement
void RequestHeaderValidator::ValidateHeaders(std::string &headers) {}

void RequestHeaderValidator::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &pseudo_headers) {
  static constexpr std::array<std::string_view, 3> kRequiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : kRequiredHeaders) {
    if (pseudo_headers.find(std::string(header)) == pseudo_headers.end()) {
      // LOG("Failed to validate pseudo-headers (missing header field)");
      pseudo_headers[":method"] = "BR";
      pseudo_headers[":path"] = "";
      return;
    }
  }
}

// TODO(QQueke): Implement
void ResponseHeaderValidator::ValidateHeaders(std::string &headers) {}

void ResponseHeaderValidator::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &pseudo_headers) {
  static constexpr std::array<std::string_view, 1> kRequiredHeaders = {
      ":status"};

  for (const auto &header : kRequiredHeaders) {
    if (pseudo_headers.find(std::string(header)) == pseudo_headers.end()) {
      // LOG("Failed to validate pseudo-headers (missing header field)");
      pseudo_headers[":status"] = "500";
      return;
    }
  }
}
