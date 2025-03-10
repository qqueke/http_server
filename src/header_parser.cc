#include "header_parser.h"

#include <algorithm>
#include <memory>

void HeaderParser::ValidateRequestHeaders(std::string &headers) {
  req_parser_.ValidateHeaders(headers);
}

void HeaderParser::ValidateResponseHeaders(std::string &headers) {
  res_parser_.ValidateHeaders(headers);
}

// Validate request pseudo-headers
void HeaderParser::ValidateRequestPseudoHeaders(
    std::unordered_map<std::string, std::string> &pseudo_headers) {
  req_parser_.ValidatePseudoHeaders(pseudo_headers);
}

void HeaderParser::ValidateResponsePseudoHeaders(
    std::unordered_map<std::string, std::string> &pseudo_headers) {
  res_parser_.ValidatePseudoHeaders(pseudo_headers);
}

std::unordered_map<std::string, std::string>
HeaderParser::ConvertRequestToPseudoHeaders(std::string_view headers) {
  return req_parser_.ConvertToPseudoHeaders(headers);
}

std::unordered_map<std::string, std::string>
HeaderParser::ConvertResponseToPseudoHeaders(std::string_view headers) {
  return res_parser_.ConvertToPseudoHeaders(headers);
}

std::unordered_map<std::string, std::string>
RequestHeaderParser::ConvertToPseudoHeaders(const std::string_view headers) {
  std::unordered_map<std::string, std::string> headers_map;
  headers_map.reserve(3);

  size_t pos = 0;
  size_t line_end = headers.find("\n", pos);

  // Parse first line individually for method, scheme and path
  if (line_end != std::string_view::npos) {
    std::string_view line = headers.substr(pos, line_end - pos);

    if (!line.empty() && line.back() == '\r') {
      line = line.substr(0, line.size() - 1);
    }

    size_t first_space = line.find(' ');
    if (first_space != std::string_view::npos) {
      size_t second_space = line.find(' ', first_space + 1);
      if (second_space != std::string_view::npos) {
        headers_map[":method"] = std::string(line.substr(0, first_space));
        headers_map[":scheme"] = "https";
        headers_map[":path"] = std::string(
            line.substr(first_space + 1, second_space - first_space - 1));
      }
    }
    pos = line_end + 1;
  }

  // Read header fields
  while (pos < headers.size()) {
    line_end = headers.find("\n", pos);
    if (line_end == std::string_view::npos)
      break;

    std::string_view line = headers.substr(pos, line_end - pos);

    // Trim \r
    if (!line.empty() && line.back() == '\r') {
      line = line.substr(0, line.size() - 1);
    }

    // If the line is empty, we reached the end of headers (\r\n\r\n)
    if (line.empty())
      break;

    size_t colon_pos = line.find(':');
    if (colon_pos != std::string_view::npos) {
      std::string key = std::string(line.substr(0, colon_pos));
      std::string value = std::string(line.substr(colon_pos + 1));

      // Trim leading space in value
      size_t value_start = value.find_first_not_of(" ");
      if (value_start != std::string::npos) {
        value = value.substr(value_start);
      }

      if (key != "Connection") {
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        headers_map[key] = value;
      }
    }

    pos = line_end + 1;
  }

  return headers_map;
}

void RequestHeaderParser::ValidateHeaders(std::string &headers) {
  validator_.ValidateHeaders(headers);
}

void RequestHeaderParser::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &pseudo_headers) {
  validator_.ValidatePseudoHeaders(pseudo_headers);
}

std::unordered_map<std::string, std::string>
ResponseHeaderParser::ConvertToPseudoHeaders(const std::string_view headers) {
  std::unordered_map<std::string, std::string> headers_map;
  headers_map.reserve(3);

  size_t pos = 0;
  size_t line_end = headers.find("\n", pos);

  // Parse first line individually for status code
  if (line_end != std::string_view::npos) {
    std::string_view line = headers.substr(pos, line_end - pos);

    if (!line.empty() && line.back() == '\r') {
      line = line.substr(0, line.size() - 1);
    }

    size_t first_space = line.find(' ');
    if (first_space != std::string_view::npos) {
      size_t second_space = line.find(' ', first_space + 1);
      if (second_space != std::string_view::npos) {
        headers_map[":status"] = std::string(
            line.substr(first_space + 1, second_space - first_space - 1));
      }
    }
    pos = line_end + 1;
  } else {
    headers_map[":status"] = "500";
  }

  // Read header fields
  while (pos < headers.size()) {
    line_end = headers.find("\n", pos);
    if (line_end == std::string_view::npos)
      break;

    std::string_view line = headers.substr(pos, line_end - pos);

    // Trim \r
    if (!line.empty() && line.back() == '\r') {
      line = line.substr(0, line.size() - 1);
    }

    // If the line is empty, we reached the end of headers (\r\n\r\n)
    if (line.empty())
      break;

    size_t colon_pos = line.find(':');
    if (colon_pos != std::string_view::npos) {
      std::string key = std::string(line.substr(0, colon_pos));
      std::string value = std::string(line.substr(colon_pos + 1));

      // Trim leading space in value
      size_t value_start = value.find_first_not_of(" ");
      if (value_start != std::string::npos) {
        value = value.substr(value_start);
      }

      if (key != "Connection") {
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        headers_map[key] = value;
      }
    }

    pos = line_end + 1;
  }

  return headers_map;
}

void ResponseHeaderParser::ValidateHeaders(std::string &headers) {
  validator_.ValidateHeaders(headers);
}

void ResponseHeaderParser::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &pseudo_headers) {
  validator_.ValidatePseudoHeaders(pseudo_headers);
}
