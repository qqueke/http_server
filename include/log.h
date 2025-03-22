// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file Log.h
 * @brief Provides logging utilities for errors and requests.
 *
 * This file defines functions and macros for logging errors and formatted
 * requests. It includes functions for flushing logs and managing periodic log
 * flushing.
 */

#ifndef INCLUDE_LOG_H_
#define INCLUDE_LOG_H_
#include <cstdint>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

/**
 * @brief Macro for logging an error.
 *
 * This macro calls `logError()` and passes the error message, along with the
 * current file and line number.
 *
 * @param ans The error message to log.
 */
#define LogError(ans) logError((ans), __FILE__, __LINE__)

#define LOG(log) Logger::GetInstance().EnqueueLog(log, __FILE__, __LINE__)

#define LOG_REQUEST(log) Logger::GetInstance().EnqueueRequestLog(log)

/**
 * @brief Macro for logging a request.
 *
 * This macro calls `logRequest()` with the provided formatted request.
 *
 * @param ans The formatted request to log.
 */
#define LogRequest(ans) logRequest((ans))

/**
 * @brief Logs an error message along with the file and line number where it
 * occurred.
 *
 * @param error The error message to log.
 * @param file The name of the file where the error occurred.
 * @param line The line number where the error occurred.
 */
void logError(const std::string &error, const char *file, int line);

/**
 * @brief Logs a formatted request.
 *
 * @param formatedRequest The formatted request to log.
 */
void logRequest(const std::string &formatedRequest);

/**
 * @brief Flushes the logs and shuts down the logging system.
 *
 * This function ensures that all buffered logs are written to disk before
 * shutting down.
 */
void ShutdownFlush();

/**
 * @brief Periodically flushes the logs to ensure they are written to disk.
 *
 * This function is designed to be called periodically to ensure logs are
 * flushed at regular intervals.
 */
void SetPeriodicFlush();

std::optional<std::string> SetLogFiles(const std::string &error_file_path);

class Logger {
 public:
  static Logger &GetInstance(const std::string &file_path = "",
                             uint32_t max_batch_size = 1);

  Logger(const Logger &) = delete;

  Logger &operator=(const Logger &) = delete;

  void EnqueueRequestLog(const std::string &request);

  void EnqueueLog(const std::string &log, const char *file = __FILE__,
                  int line = __LINE__);
  void FlushLogs();

 private:
  explicit Logger(const std::string &file_path, uint32_t max_batch_size = 1);

  ~Logger();

  uint32_t max_batch_size_;
  std::vector<std::string> buffer_;
  std::mutex mut_;

  std::ofstream file_;
};
#endif  // INCLUDE_LOG_H_
