// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/log.h"

#include <fcntl.h>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

std::ofstream log_file;
std::mutex log_mut;
static std::vector<std::string> log_buffer;

const size_t max_log_buffer_size = 1;

std::optional<std::string> SetLogFiles(const std::string &error_file_path) {
  log_file.open(error_file_path, std::ios::app);
  if (!log_file.is_open()) {
    return "Could not open log file\n";
  }
  return std::nullopt;
}

inline void FlushLogsToFile(std::ofstream &file,
                            std::vector<std::string> &buffer) {
  for (const auto &log : buffer) {
    file << log << "\n";
  }

  buffer.clear();
  std::flush(file);
}

void ShutdownFlush() {
  if (!log_buffer.empty()) {
    std::lock_guard<std::mutex> lock(log_mut);
    FlushLogsToFile(log_file, log_buffer);
  }

  std::cout << "Shutdown flush done." << std::endl;
}

void SetPeriodicFlush() {
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(60));

    if (!log_buffer.empty()) {
      std::lock_guard<std::mutex> lock(log_mut);
      FlushLogsToFile(log_file, log_buffer);
    }
  }
}

inline auto GetTimestamp() {
  auto now = std::chrono::system_clock::now();
  std::time_t t_c = std::chrono::system_clock::to_time_t(now);

  std::string timeStr = std::ctime(&t_c);

  if (!timeStr.empty() && timeStr.back() == '\n') {
    timeStr.pop_back();
  }
  return timeStr;
}

void logError(const std::string &log, const char *file, int line) {
  std::string log_entry = GetTimestamp()
                              .append(": ")
                              .append(log)
                              .append(" in file: ")
                              .append(file)
                              .append(" at line: ")
                              .append((std::to_string(line)));

  std::lock_guard<std::mutex> lock(log_mut);
  log_buffer.emplace_back(log_entry);

  if (log_buffer.size() >= max_log_buffer_size) {
    FlushLogsToFile(log_file, log_buffer);
  }
}

void logRequest(const std::string &request) {
  std::string log_entry = GetTimestamp() + ": " + request;

  std::lock_guard<std::mutex> lock(log_mut);
  log_buffer.emplace_back(log_entry);

  // If the buffer size exceeds the max threshold, flush to file
  if (log_buffer.size() >= max_log_buffer_size) {
    FlushLogsToFile(log_file, log_buffer);
  }
}

Logger &Logger::GetInstance(const std::string &file_path,
                            uint32_t max_batch_size) {
  static Logger instance(file_path, max_batch_size);
  return instance;
}

Logger::Logger(const std::string &file_path, uint32_t max_batch_size) {
  file_.open(file_path, std::ios::app);

  if (!file_.is_open()) {
    // How do we handle this?
  }

  max_batch_size_ = max_batch_size;
  buffer_.reserve(max_batch_size_);
}

Logger::~Logger() { file_.close(); }

void Logger::EnqueueRequestLog(const std::string &request) {
  std::string log_entry = GetTimestamp() + ": " + request;

  std::lock_guard<std::mutex> lock(mut_);
  buffer_.emplace_back(log_entry);

  if (buffer_.size() >= max_batch_size_) {
    FlushLogs();
  }
}

void Logger::EnqueueLog(const std::string &log, const char *file, int line) {
  std::string log_entry = GetTimestamp()
                              .append(": ")
                              .append(log)
                              .append(" in file: ")
                              .append(file)
                              .append(" at line: ")
                              .append((std::to_string(line)));

  std::lock_guard<std::mutex> lock(mut_);
  buffer_.emplace_back(log_entry);

  if (buffer_.size() >= max_batch_size_) {
    FlushLogs();
  }
}

void Logger::FlushLogs() {
  for (const auto &log : buffer_) {
    file_ << log << "\n";
  }

  buffer_.clear();
  std::flush(file_);
}
