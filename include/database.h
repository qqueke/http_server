// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_DATABASE_H_
#define INCLUDE_DATABASE_H_
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

#include "../include/database_tables.h"

class Database {
 public:
  ~Database();

  Database(const Database &) = delete;

  Database &operator=(const Database &) = delete;

  static std::shared_ptr<Database> GetInstance();

  int Add(const std::string &table_name, const std::string &data);

  int Delete(const std::string &table_name, const std::string &data);

  std::optional<std::string> Search(const std::string &table_name,
                                    const std::string &data);

 private:
  Database();

  static std::weak_ptr<Database> instance_;

  static std::mutex instance_mut_;

  std::unordered_map<std::string, std::unique_ptr<ITable>> tables_collection_;

  void InitializeIndexFromFile();
};

#endif  // INCLUDE_DATABASE_H_
