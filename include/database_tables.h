// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#ifndef INCLUDE_DATABASE_TABLES_H_
#define INCLUDE_DATABASE_TABLES_H_

#include <cstdint>
#include <optional>
#include <string>

enum TableOp : uint8_t {
  ADD = 0,
  DELETE = 1,
  SEARCH = 2,
};

class ITable {
 public:
  virtual ~ITable() = default;

  virtual int Add(const std::string &data) = 0;

  virtual int Delete(const std::string &data) = 0;

  // This function looks for indexing field
  virtual std::optional<std::string> Search(const std::string &data) = 0;

  virtual std::string GetDeleteKeyFromAddData(const std::string &data) = 0;

  virtual std::optional<std::string> GetAddDataFromDeleteKey(
      const std::string &data) = 0;

 private:
  void FlushToFile();
};

#endif  // INCLUDE_DATABASE_TABLES_H_
