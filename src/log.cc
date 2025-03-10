// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/log.h"

#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

std::ofstream errorFile("logs/error.log", std::ios::app);
std::ofstream requestLogFile("logs/requests.log", std::ios::app);

std::mutex stderrMutex;
std::mutex stdoutMutex;

const size_t maxLogBatchSize = 1;

static std::vector<std::string> errorBuffer;
static std::vector<std::string> requestBuffer;

inline void flushLogsToFile(std::ofstream &file,
                            std::vector<std::string> &buffer) {
  for (const auto &log : buffer) {
    file << log << "\n";
  }

  buffer.clear();
  std::flush(file);
}

void shutdownFlush() {
  if (!errorBuffer.empty()) {
    std::lock_guard<std::mutex> lock(stderrMutex);
    flushLogsToFile(errorFile, errorBuffer);
  }

  if (!requestBuffer.empty()) {
    std::lock_guard<std::mutex> lock(stdoutMutex);
    flushLogsToFile(requestLogFile, requestBuffer);
  }

  std::cout << "Shutdown flush done." << std::endl;
}

void periodicFlush() {
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(60));

    if (!errorBuffer.empty()) {
      std::lock_guard<std::mutex> lock(stderrMutex);
      flushLogsToFile(errorFile, errorBuffer);
    }

    if (!requestBuffer.empty()) {
      std::lock_guard<std::mutex> lock(stdoutMutex);
      flushLogsToFile(requestLogFile, requestBuffer);
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

  std::lock_guard<std::mutex> lock(stderrMutex);
  errorBuffer.emplace_back(logEntry);

  if (errorBuffer.size() >= maxLogBatchSize) {
    flushLogsToFile(errorFile, errorBuffer);
  }
}

void logRequest(const std::string &formatedRequest) {
  std::string logEntry = getTimestamp() + ": " + formatedRequest;

  std::lock_guard<std::mutex> lock(stdoutMutex);
  requestBuffer.emplace_back(logEntry);

  // If the buffer size exceeds the max threshold, flush to file
  if (requestBuffer.size() >= maxLogBatchSize) {
    flushLogsToFile(requestLogFile, requestBuffer);
  }
}
