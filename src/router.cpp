#include "router.hpp"
#include "log.hpp"
#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <string>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <zlib.h>

// Compatability with Windows/MS-DOS systems.
#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#include <fcntl.h>
#include <io.h>
#define SET_BINARY_MODE(file) _setmode(_fileno(file), O_BINARY)
#else
#define SET_BINARY_MODE(file)
#endif

#define CHUNK 16384

static std::unordered_map<std::string, std::string> responseCache;
static std::mutex responseMutex;

static std::unordered_map<std::string, std::string> fileCache;
static std::mutex cacheMutex;

Router::Router() = default;
Router::Router(const Router &) = default;
Router &Router::operator=(const Router &) = default;

void Router::addRoute(
    const std::string &method, const std::string &path,
    const std::function<std::string(SSL *, const std::string)> &handler) {
  routes[{method, path}] = handler;
}

std::string Router::routeRequest(const std::string &method,
                                 const std::string &path, SSL *clientSock) {
  std::string cacheKey = method + " " + path;

  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    if (responseCache.find(cacheKey) != responseCache.end()) {
      std::cout << "Cache hit for: " << cacheKey << "\n";
      SSL_write(clientSock, responseCache[cacheKey].c_str(),
                (int)responseCache[cacheKey].size());

      // Extract the response from the cache
      std::string response = responseCache[cacheKey];

      // Find where the protocol (e.g., HTTP/1.1) ends by looking for the first
      // space after "HTTP/"
      size_t protocolEndPos = response.find(
          ' ', 5); // After "HTTP/", we want to find the first space

      // Extract the status code and message starting after the protocol
      size_t statusEndPos =
          response.find("\r\n", protocolEndPos); // End at the first \r\n

      std::string statusLine = response.substr(
          protocolEndPos + 1, statusEndPos - protocolEndPos - 1);

      std::cout << "Status: " << statusLine
                << "\n"; // Print status code + message

      // Extract status code or save as struct instead of std::string response
      return statusLine;
    }
  }

  // Not Allowed
  if (method == "NA") {
    return handleMethodNotAllowed(clientSock, cacheKey);
  } else if (method == "NF") {
    return handleNotFound(clientSock, cacheKey);
  } else if (method == "BR") {
    return handleBadRequest(clientSock, cacheKey);
  } else if (method == "LR") {
    return handleLengthRequired(clientSock, cacheKey);
  } else if (method == "UP") {
    return handleUnsupportedProtocol(clientSock, cacheKey);
  } else if (method == "CL") {
    return handleConnectionsLimit(clientSock, cacheKey);
  } else if (method == "FV") {
    return handleValidationFailure(clientSock, cacheKey);
  }

  std::pair<std::string, std::string> routeKey = std::make_pair(method, path);

  if (routes.find(routeKey) != routes.end()) {
    return routes[routeKey](clientSock, cacheKey);
  } else {
    std::cout << "Error: Undefined route\n";
    return "";
  }
  return "";
}

static void verifyContentType(const std::string &filePath,
                              std::string &httpResponse) {

  std::string fileExtension{};
  for (int pos = (int)filePath.size() - 1; pos >= 0; --pos) {
    if (filePath[pos] == '.') {
      fileExtension = filePath.substr(pos, filePath.size() - pos);
    }
  }

  if (fileExtension == ".html") {
    httpResponse += "Content-Type: text/html\r\n";
  }
  if (fileExtension == ".css") {
    httpResponse += "Content-Type: text/css\r\n";
  }
  if (fileExtension == ".js") {
    httpResponse += "Content-Type: text/javascript\r\n";
  }
  if (fileExtension == ".json") {
    httpResponse += "Content-Type: application/json\r\n";
  }
  if (fileExtension == ".xml") {
    httpResponse += "Content-Type: application/xml\r\n";
  }
  if (fileExtension == ".txt") {
    httpResponse += "Content-Type: text/plain\r\n";
  }
  if (fileExtension == ".jpg") {
    httpResponse += "Content-Type: image/jpeg\r\n";
  }
  if (fileExtension == ".jpeg") {
    httpResponse += "Content-Type: image/jpeg\r\n";
  }
  if (fileExtension == ".png") {
    httpResponse += "Content-Type: image/png\r\n";
  }
  if (fileExtension == ".gif") {
    httpResponse += "Content-Type: image/gif\r\n";
  }
  if (fileExtension == ".svg") {
    httpResponse += "Content-Type: text/svg\r\n";
  }
  if (fileExtension == ".webp") {
    httpResponse += "Content-Type: image/webp\r\n";
  }
  if (fileExtension == ".mp3") {
    httpResponse += "Content-Type: audio/mpeg\r\n";
  }
  if (fileExtension == ".wav") {
    httpResponse += "Content-Type: audio/wav\r\n";
  }
  if (fileExtension == ".mp4") {
    httpResponse += "Content-Type: video/mp4\r\n";
  }
  if (fileExtension == ".webm") {
    httpResponse += "Content-Type: video/webm\r\n";
  }
  if (fileExtension == ".woff") {
    httpResponse += "Content-Type: font/woff\r\n";
  }
  if (fileExtension == ".woff2") {
    httpResponse += "Content-Type: font/woff2\r\n";
  }
  if (fileExtension == ".ttf") {
    httpResponse += "Content-Type: font/ttf\r\n";
  }
  if (fileExtension == ".otf") {
    httpResponse += "Content-Type: font/otf\r\n";
  }
  if (fileExtension == ".pdf") {
    httpResponse += "Content-Type: application/pdf\r\n";
  }
  if (fileExtension == ".zip") {
    httpResponse += "Content-Type: application/zip\r\n";
  }
  if (fileExtension == ".gz") {
    httpResponse += "Content-Type: application/gzip\r\n";
  }

  httpResponse += "\r\n";
}

static void sendFile(SSL *clientSSL, const std::string &filePath,
                     bool acceptEncoding) {

  int fileFd = open(filePath.c_str(), O_RDONLY);

  struct stat fileStat{};
  if (fstat(fileFd, &fileStat) == -1) {
    LogError("Error getting file stats");
    close(fileFd);
    return;
  }

  std::string httpResponse = "HTTP/1.1 200 OK\r\n";
  httpResponse +=
      "Content-Length: " + std::to_string(fileStat.st_size) + "\r\n";

  if (acceptEncoding) {
    httpResponse += "Content-Encoding: gzip\r\n";
  }

  verifyContentType(filePath, httpResponse);

  // verify  content type
  ssize_t bytesSent =
      SSL_write(clientSSL, httpResponse.data(), (int)httpResponse.size());

  if (bytesSent <= 0) {
    int err = SSL_get_error(clientSSL, (int)bytesSent);
    LogError("SSL_write failed: " + std::to_string(err));
    close(fileFd);
    return;
  }

  if (BIO_get_ktls_send(SSL_get_wbio(clientSSL))) {
    bytesSent = SSL_sendfile(clientSSL, fileFd, 0, fileStat.st_size, 0);
    if (bytesSent >= 0) {
      close(fileFd);
      return;
    }
    LogError("SSL_sendfile failed, falling back to manual send");
  }

  std::array<char, 4096> buffer{};

  while (read(fileFd, buffer.data(), buffer.size()) > 0) {

    bytesSent = SSL_write(clientSSL, buffer.data(), buffer.size());

    if (bytesSent <= 0) {
      int err = SSL_get_error(clientSSL, (int)bytesSent);
      LogError("SSL_write failed: " + std::to_string(err));
      close(fileFd);
      return;
    }
  }

  close(fileFd);
}

enum CompressionType { DEFLATE, GZIP };

bool compressData(const std::string &inputFile, const std::string &outputFile,
                  CompressionType type) {
  std::ifstream inFileStream(inputFile, std::ios::binary);
  if (!inFileStream) {
    LogError("Failed to open input file\n");
    return false;
  }

  // Create output file
  std::ofstream file(outputFile, std::ios::binary | std::ios::out);
  file.close();

  std::ofstream outFileStream(outputFile, std::ios::binary);
  if (!outFileStream) {
    LogError("Failed to open output file\n");
    return false;
  }

  // Will read file stream as chars until end of file ({}), to the vector
  std::vector<char> buffer(std::istreambuf_iterator<char>(inFileStream), {});

  uLongf compressedSize = compressBound(buffer.size());
  std::vector<Bytef> compressedData(compressedSize);

  z_stream zStream = {};
  zStream.next_in = reinterpret_cast<Bytef *>(buffer.data());
  zStream.avail_in = buffer.size();
  zStream.next_out = compressedData.data();
  zStream.avail_out = compressedSize;

  int windowBits =
      (type == GZIP) ? 15 + 16 : 15; // 15 for Deflate, +16 for Gzip

  if (deflateInit2(&zStream, Z_BEST_COMPRESSION, Z_DEFLATED, windowBits, 8,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    LogError("Compression initialization failed\n");
    return false;
  }

  if (deflate(&zStream, Z_FINISH) != Z_STREAM_END) {
    LogError("Compression failed\n");
    deflateEnd(&zStream);
    return false;
  }

  outFileStream.write(reinterpret_cast<const char *>(compressedData.data()),
                      (long)zStream.total_out);

  deflateEnd(&zStream);

  std::cout << ((type == GZIP) ? "Gzip" : "Deflate")
            << " compression successful: " << outputFile << "\n";
  return true;
}

void Router::staticFileHandler(SSL *clientSSL, const std::string &filePath,
                               bool acceptEncoding) {

  if (acceptEncoding) {
    // find if a precomputed compressed file exists and send it
    struct stat buf{};
    int err = stat((filePath + ".gz").c_str(), &buf);
    // file exists
    if (err == 0) {
      sendFile(clientSSL, filePath + ".gz", acceptEncoding);
      return;
    }

    // otherwise compress it on the fly and send It
    if (compressData(filePath, filePath + ".gz", GZIP)) {
      sendFile(clientSSL, filePath + ".gz", acceptEncoding);
      return;
    }

    LogError("Compression failed, falling back to full file");
  }

  sendFile(clientSSL, filePath, acceptEncoding);
}

void Router::storeInCache(const std::string &cacheKey,
                          const std::string &response) {
  std::lock_guard<std::mutex> lock(cacheMutex);
  responseCache[cacheKey] = response;
}

/* --------------------------------------------------------------------------------*/
/* --------------------------------------------------------------------------------*/
/* --------------------------------------------------------------------------------*/
/* ---------------------------Default Methods
 * -----------------------------------*/
/* --------------------------------------------------------------------------------*/
/* --------------------------------------------------------------------------------*/
/* --------------------------------------------------------------------------------*/

std::string Router::handleMethodNotAllowed(SSL *clientSock,
                                           const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 405 Method Not Allowed\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 18\r\n"
                             "\r\n"
                             "Method Not Allowed";
  ssize_t bytesSent = SSL_write(clientSock, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {
    LogError("Failed to send response");
  }

  storeInCache(cacheKey, std::string(httpResponse));

  return "405 Method Not Allowed";
}

std::string Router::handleNotFound(SSL *clientSock,
                                   const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 404 Not Found\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 9\r\n"
                             "\r\n"
                             "Not Found";
  ssize_t bytesSent = SSL_write(clientSock, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {
    LogError("Failed to send response");
  }

  storeInCache(cacheKey, std::string(httpResponse));

  return "404 Not Found";
}

std::string Router::handleBadRequest(SSL *clientSock,
                                     const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 400 Bad Request\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 20\r\n"
                             "\r\n"
                             "Malformed Header";
  ssize_t bytesSent = SSL_write(clientSock, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {

    LogError("Failed to send response");
  }

  storeInCache(cacheKey, std::string(httpResponse));

  return "400 Bad Request";
}

std::string Router::handleLengthRequired(SSL *clientSock,
                                         const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 411 Length Required\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 15\r\n"
                             "\r\n"
                             "Length Required";
  ssize_t bytesSent = SSL_write(clientSock, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {
    LogError("Failed to send response");
  }

  storeInCache(cacheKey, std::string(httpResponse));

  return "411 Length Required";
}

std::string Router::handleUnsupportedProtocol(SSL *clientSock,
                                              const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 505 HTTP Version Not Supported\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 24\r\n"
                             "\r\n"
                             "HTTP Version Not Supported";
  ssize_t bytesSent = SSL_write(clientSock, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {

    LogError("Failed to send response");
  }

  storeInCache(cacheKey, std::string(httpResponse));

  return "505 HTTP Version Not Supported";
}

std::string Router::handleConnectionsLimit(SSL *clientSock,
                                           const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 503 Service Unavailable\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 13\r\n"
                             "\r\n"
                             "Server Busy";
  ssize_t bytesSent = SSL_write(clientSock, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {

    LogError("Failed to send response");
  }

  storeInCache(cacheKey, std::string(httpResponse));

  return "503 Service Unavailable";
}

std::string Router::handleValidationFailure(SSL *clientSock,
                                            const std::string &cacheKey) {
  const char *httpResponse = "HTTP/1.1 400 Bad Request\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: 23\r\n"
                             "\r\n"
                             "Failed to Validate Request";
  ssize_t bytesSent = SSL_write(clientSock, httpResponse, strlen(httpResponse));
  if (bytesSent <= 0) {
    LogError("Failed to send response");
  }

  storeInCache(cacheKey, std::string(httpResponse));
  return "400 Bad Request";
}
