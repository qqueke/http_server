// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_ROUTES_H_
#define INCLUDE_ROUTES_H_

#include <memory>
#include <string>
#include <utility>

#include "../include/database.h"

class Routes {
 public:
  explicit Routes(const std::shared_ptr<Database> &db);

  ~Routes();

  static std::pair<std::string, std::string> HelloHandler(
      const std::string &data);

  static std::pair<std::string, std::string> EchoHandler(
      const std::string &data);

  static std::pair<std::string, std::string> AddUser(const std::string &data);

  static std::pair<std::string, std::string> SearchUser(
      const std::string &data);

  static std::pair<std::string, std::string> DeleteUser(
      const std::string &data);

 private:
  static bool static_init_;

  static std::weak_ptr<Database> db_;

  void InitializeSharedResources(const std::shared_ptr<Database> &db);
};
#endif  // INCLUDE_ROUTES_H_
