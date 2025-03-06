#ifndef LOG_H
#define LOG_H

#include <fstream>

#define LogError(ans) logError((ans), __FILE__, __LINE__)
#define LogRequest(ans) logRequest((ans))

void logError(const std::string &error, const char *file, int line);
void logRequest(const std::string &formatedRequest);

void shutdownFlush();
void periodicFlush();

#endif // LOG_H
