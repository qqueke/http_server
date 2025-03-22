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

/**
 * @class Logger
 * @brief A singleton class for logging system requests and messages.
 *
 * The `Logger` class is responsible for logging various messages in the system.
 * It supports batching log entries and flushing them to a file. It ensures that
 * logs are written to a file efficiently by storing them in a buffer and only
 * flushing them when necessary.
 */
class Logger {
 public:
  /**
   * @brief Gets the singleton instance of the Logger.
   *
   * This method provides access to the global Logger instance. If the instance
   * does not exist, it is created with the given file path and maximum batch
   * size for the logs.
   *
   * @param file_path The path to the log file. If empty, no file will be used.
   * @param max_batch_size The maximum number of logs to store in the buffer
   * before flushing.
   * @return A reference to the Logger instance.
   */
  static Logger &GetInstance(const std::string &file_path = "",
                             uint32_t max_batch_size = 1);

  /**
   * @brief Deleted copy constructor to prevent copying of the Logger instance.
   */
  Logger(const Logger &) = delete;

  /**
   * @brief Deleted copy assignment operator to prevent assigning a new Logger
   * instance.
   */
  Logger &operator=(const Logger &) = delete;

  /**
   * @brief Enqueues a request log into the logger buffer.
   *
   * This method adds a log entry related to a request to the internal log
   * buffer. The log entry will be flushed once the batch size is reached.
   *
   * @param request The request message to log.
   */
  void EnqueueRequestLog(const std::string &request);

  /**
   * @brief Enqueues a custom log message into the logger buffer.
   *
   * This method adds a custom log entry to the internal log buffer, including
   * the file name and line number where the log was generated.
   *
   * @param log The custom log message.
   * @param file The file name from which the log was generated (defaults to the
   * current file).
   * @param line The line number in the file from which the log was generated
   * (defaults to the current line).
   */
  void EnqueueLog(const std::string &log, const char *file = __FILE__,
                  int line = __LINE__);

  /**
   * @brief Flushes all logs in the buffer to the log file.
   *
   * This method writes all accumulated logs in the buffer to the log file and
   * clears the buffer.
   */
  void FlushLogs();

 private:
  /**
   * @brief Private constructor for initializing the Logger instance.
   *
   * The constructor initializes the log file path and max batch size for the
   * logger.
   *
   * @param file_path The path to the log file.
   * @param max_batch_size The maximum number of logs to store in the buffer
   * before flushing.
   */
  explicit Logger(const std::string &file_path, uint32_t max_batch_size = 1);

  /**
   * @brief Destructor for cleaning up the Logger instance.
   *
   * The destructor ensures that all logs are flushed to the file before the
   * logger is destroyed.
   */
  ~Logger();

  /**
   * @brief The maximum number of logs to store before flushing them to the
   * file.
   */
  uint32_t max_batch_size_;

  /**
   * @brief The buffer where log messages are temporarily stored before being
   * flushed.
   */
  std::vector<std::string> buffer_;

  /**
   * @brief Mutex for thread-safe access to the log buffer.
   */
  std::mutex mut_;

  /**
   * @brief The file stream where logs are written.
   */
  std::ofstream file_;
};

#endif  // INCLUDE_LOG_H_
