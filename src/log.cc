// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/log.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

std::ofstream error_file("logs/error.log", std::ios::app);
std::ofstream requests_log_file("logs/requests.log", std::ios::app);

std::mutex stderr_mut;
std::mutex stdout_mut;

const size_t maxLogBatchSize = 1;

static std::vector<std::string> error_buffer;
static std::vector<std::string> request_buffer;

inline void flushLogsToFile(std::ofstream &file,
                            std::vector<std::string> &buffer) {
  for (const auto &log : buffer) {
    file << log << "\n";
  }

  buffer.clear();
  std::flush(file);
}

void shutdownFlush() {
  if (!error_buffer.empty()) {
    std::lock_guard<std::mutex> lock(stderr_mut);
    flushLogsToFile(error_file, error_buffer);
  }

  if (!request_buffer.empty()) {
    std::lock_guard<std::mutex> lock(stdout_mut);
    flushLogsToFile(requests_log_file, request_buffer);
  }

  std::cout << "Shutdown flush done." << std::endl;
}

void periodicFlush() {
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(60));

    if (!error_buffer.empty()) {
      std::lock_guard<std::mutex> lock(stderr_mut);
      flushLogsToFile(error_file, error_buffer);
    }

    if (!request_buffer.empty()) {
      std::lock_guard<std::mutex> lock(stdout_mut);
      flushLogsToFile(requests_log_file, request_buffer);
    }
  }
}

inline auto getTimestamp() {
  auto now = std::chrono::system_clock::now();
  std::time_t t_c = std::chrono::system_clock::to_time_t(now);

  std::string timeStr = std::ctime(&t_c);

  if (!timeStr.empty() && timeStr.back() == '\n') {
    timeStr.pop_back();
  }
  return timeStr;
}

void logError(const std::string &error, const char *file, int line) {
  std::ostringstream logStream;
  logStream << getTimestamp() << ": " << error << " in file: " << file
            << " at line: " << line;

  std::string logEntry = logStream.str();

  std::lock_guard<std::mutex> lock(stderr_mut);
  error_buffer.emplace_back(logEntry);

  if (error_buffer.size() >= maxLogBatchSize) {
    flushLogsToFile(error_file, error_buffer);
  }
}

void logRequest(const std::string &formatedRequest) {
  std::string logEntry = getTimestamp() + ": " + formatedRequest;

  std::lock_guard<std::mutex> lock(stdout_mut);
  request_buffer.emplace_back(logEntry);

  // If the buffer size exceeds the max threshold, flush to file
  if (request_buffer.size() >= maxLogBatchSize) {
    flushLogsToFile(requests_log_file, request_buffer);
  }
}
