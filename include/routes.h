// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_ROUTES_H_
#define INCLUDE_ROUTES_H_

#include <string>
#include <utility>

class Routes {
 public:
  explicit Routes();

  ~Routes();

  static std::pair<std::string, std::string> HelloHandler(
      const std::string &data);

  static std::pair<std::string, std::string> EchoHandler(
      const std::string &data);
};
#endif  // INCLUDE_ROUTES_H_
