#include "server.hpp"

#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>

#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
#include "log.hpp"
#include "router.hpp"
#include "sCallbacks.hpp"
#include "utils.hpp"

static std::unordered_map<std::string, std::string> responseCache;
static std::mutex responseMutex;
static std::mutex cacheMutex;

std::atomic<bool> shouldShutdown(false);

HTTPServer *HTTPServer::instance = nullptr;
std::mutex HTTPServer::instanceMutex;

int HTTPServer::dhiProcessHeader(void *hblock_ctx,
                                 struct lsxpack_header *xhdr) {
  // printf("dhi_process_header: xhdr=%lu\n", (size_t)xhdr);
  // printf("%.*s: %.*s\n", xhdr->name_len, (xhdr->buf + xhdr->name_offset),
  //        xhdr->val_len, (xhdr->buf + xhdr->val_offset));

  std::string headerKey(xhdr->buf + xhdr->name_offset, xhdr->name_len);
  std::string headerValue(xhdr->buf + xhdr->val_offset, xhdr->val_len);

  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx;
  // block_ctx->stream
  HTTPServer *server = HTTPServer::GetInstance();

  server->DecodedHeadersMap[block_ctx->stream][headerKey] = headerValue;

  return 0;
}

void HTTPServer::UQPACKHeadersServer(HQUIC stream,
                                     std::vector<uint8_t> &encodedHeaders) {
  std::vector<struct lsqpack_dec> dec(1);

  struct lsqpack_dec_hset_if hset_if;
  hset_if.dhi_unblocked = dhiUnblocked;
  hset_if.dhi_prepare_decode = dhiPrepareDecode;
  hset_if.dhi_process_header = dhiProcessHeader;

  enum lsqpack_dec_opts dec_opts {};
  lsqpack_dec_init(dec.data(), NULL, 0x1000, 0, &hset_if, dec_opts);

  // hblock_ctx_t *blockCtx = (hblock_ctx_t *)malloc(sizeof(hblock_ctx_t));

  std::vector<hblock_ctx_t> blockCtx(1);

  memset(&blockCtx.back(), 0, sizeof(hblock_ctx_t));
  blockCtx.back().stream = stream;

  const unsigned char *encodedHeadersPtr = encodedHeaders.data();
  size_t totalHeaderSize = encodedHeaders.size();

  enum lsqpack_read_header_status readStatus;

  readStatus =
      lsqpack_dec_header_in(dec.data(), &blockCtx.back(), 100, totalHeaderSize,
                            &encodedHeadersPtr, totalHeaderSize, NULL, NULL);

  // printf("lsqpack_dec_header_in return = %d, const_end_header_buf = %lu, "
  //        "end_header_buf = %lu\n",
  //        read_status, (size_t)all_header_ptr, (size_t)all_header);

  // std::cout << "--------------------------------------------\n";
  // std::cout << "-----------Decoding finished ---------------\n";
  // std::cout << "--------------------------------------------\n";
}

void HTTPServer::ParseStreamBuffer(HQUIC Stream,
                                   std::vector<uint8_t> &streamBuffer,
                                   std::string &data) {
  auto iter = streamBuffer.begin();

  while (iter < streamBuffer.end()) {
    // Ensure we have enough data for a frame (frameType + frameLength)
    if (std::distance(iter, streamBuffer.end()) < 3) {
      std::cout << "Error: Bad frame format (Not enough data)\n";
      break;
    }

    // Read the frame type
    uint64_t frameType = ReadVarint(iter, streamBuffer.end());

    // Read the frame length
    uint64_t frameLength = ReadVarint(iter, streamBuffer.end());

    // Ensure the payload doesn't exceed the bounds of the buffer
    if (std::distance(iter, streamBuffer.end()) < frameLength) {
      std::cout << "Error: Payload exceeds buffer bounds\n";
      break;
    }

    // Handle the frame based on the type
    switch (frameType) {
    case 0x01: // HEADERS frame
      std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

      {
        std::vector<uint8_t> encodedHeaders(iter, iter + frameLength);

        UQPACKHeadersServer(Stream, encodedHeaders);

        // headers = std::string(iter, iter + frameLength);
      }
      break;

    case 0x00: // DATA frame
      std::cout << "[strm][" << Stream << "] Received DATA frame\n";
      // Data might have been transmitted over multiple frames
      data += std::string(iter, iter + frameLength);
      break;

    default: // Unknown frame type
      std::cout << "[strm][" << Stream << "] Unknown frame type: 0x" << std::hex
                << frameType << std::dec << "\n";
      break;
    }

    iter += frameLength;
  }
  // std::cout << headers << data << "\n";

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < streamBuffer.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << Stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    streamBuffer.end() - iter);
    std::cout << std::endl;
  }
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

std::string HTTPServer::threadSafeStrerror(int errnum) {
  std::lock_guard<std::mutex> lock(strerrorMutex);
  return {strerror(errnum)};
}

void HTTPServer::staticFileHandler(SSL *clientSSL, const std::string &filePath,
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

void HTTPServer::storeInCache(const std::string &cacheKey,
                              const std::string &response) {
  std::lock_guard<std::mutex> lock(cacheMutex);
  responseCache[cacheKey] = response;
}

int HTTPServer::SendHTTP1Response(SSL *clientSSL, const std::string &response) {
  ssize_t bytesSent =
      SSL_write(clientSSL, response.data(), (int)response.size());
  if (bytesSent <= 0) {
    LogError("Failed to reply to client");
    return ERROR;
  }
  return 0;
}

int HTTPServer::SendHTTP3Response(HQUIC Stream,
                                  std::vector<std::vector<uint8_t>> &frames) {
  if (SendFramesToStream(Stream, frames) == ERROR) {
    return ERROR;
  }

  return 0;
}

int HTTPServer::ValidateRequestsHTTP1(const std::string &request,
                                      std::string &method, std::string &path,
                                      bool &acceptEncoding) {
  std::istringstream requestStream(request);
  std::string line;

  std::getline(requestStream, line);
  std::istringstream requestLine(line);
  std::string protocol;
  requestLine >> method >> path >> protocol;

  if (method != "GET" && method != "POST" && method != "PUT") {
    return ERROR;
  }

  if (path.empty() || path[0] != '/' || path.find("../") != std::string::npos) {
    return ERROR;
  }

  if (protocol != "HTTP/1.1" && protocol != "HTTP/2") {
    return ERROR;
  }

  // header, value
  std::unordered_map<std::string, std::string> headers;
  while (std::getline(requestStream, line) && !line.empty()) {
    if (line.size() == 1) {
      continue;
    }

    auto colonPos = line.find(": ");
    if (colonPos == std::string::npos) {
      return ERROR;
    }

    std::string key = line.substr(0, colonPos);
    std::string value = line.substr(colonPos + 2);

    headers[key] = value;
  }

  // Validate Headers

  // If we don't  find  host then it is a bad request
  if (headers.find("Host") == headers.end()) {
    return ERROR;
  }

  // If is a POST and has  no content length it is a bad request
  if (method == "POST" && headers.find("Content-Length") == headers.end()) {
    return ERROR;
  }

  // Parse Body (if has content-length)
  std::string body;
  if (headers.find("Content-Length") != headers.end()) {
    size_t contentLength = std::stoi(headers["Content-Length"]);

    body.resize(contentLength);
    requestStream.read(body.data(), (long)contentLength);

    // If body size  doesnt match the content length defined then bad request
    if (body.size() != contentLength) {
      return ERROR;
    }
  }

  // Not even bothering with enconding type
  if (headers.find("Accept-Encoding") != headers.end()) {
    acceptEncoding = true;
  }

  // If all validations pass
  std::cout << "Request successfully validated!\n";

  return 0;
}

void HTTPServer::ValidateHeadersHTTP3(

    std::unordered_map<std::string, std::string> &headersMap) {
  // std::istringstream headersStream(headers);
  // std::string line;
  //
  // while (std::getline(headersStream, line)) {
  //   if (!line.empty() && line.back() == '\r') {
  //     line.pop_back();
  //   }
  //
  //   // Find first occurrence of ": "
  //   size_t pos = line.find(": ");
  //   if (pos != std::string::npos) {
  //     std::string key = line.substr(0, pos);
  //     std::string value = line.substr(pos + 2);
  //     headersMap[key] = value;
  //   }
  // }

  // Should probably be a variable within the class
  std::unordered_set<std::string> requiredHeaders;
  requiredHeaders.insert(":method");
  requiredHeaders.insert(":scheme");
  requiredHeaders.insert(":path");

  for (const auto &header : requiredHeaders) {
    if (headersMap.find(header) == headersMap.end()) {
      std::cout << "Missing atleast one mandatory header field\n";
      headersMap["method"] = "BR";
      headersMap["path"] = "";
      return;
    }
  }

  // If all validations pass
  std::cout << "Request successfully validated for HTTP/3!\n";
}

// void HTTPServer::clientHandlerThread(
//     int clientSock, std::chrono::high_resolution_clock::time_point startTime)
//     {
//   std::array<char, BUFFER_SIZE> buffer{};
//   std::string request;
//
//   // Create SSL object
//   SSL *ssl = SSL_new(ctx);
//
//   //  sets the file descriptor clientSock as the input/output facility for
//   the
//   //  TLS/SSL
//   SSL_set_fd(ssl, clientSock);
//
//   // TLS/SSL handshake
//   if (SSL_accept(ssl) <= 0) {
//     LogError("SSL handshake failed");
//     SSL_free(ssl);
//     close(clientSock);
//     return;
//   }
//
//   if (activeConnections >= MAX_CONNECTIONS) {
//     ServerRouter->RouteRequest("CL", "", ssl);
//     LogError("Connections limit exceeded");
//     SSL_free(ssl);
//     close(clientSock);
//     return;
//   }
//
//   activeConnections++;
//
//   std::string method{};
//   std::string path{};
//   std::string status{};
//
//   // Just to not delete the while loop
//   bool keepAlive = true;
//
//   while (!shouldShutdown && keepAlive) {
//     keepAlive = false;
//
//     ssize_t bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);
//
//     if (bytesReceived == 0) {
//       LogError("Client closed the connection");
//       break;
//     } else if (bytesReceived < 0) {
//       LogError("Failed to receive data");
//       break;
//     }
//
//     request.append(buffer.data(), bytesReceived);
//
//     while (bytesReceived == BUFFER_SIZE && !shouldShutdown) {
//       // struct pollfd pollFds(clientSock, POLLIN, 0);
//       //
//       // int polling = poll(&pollFds, 1, 0.5 * 1000);
//       // if (polling == 0) {
//       //   LogError("No more data to read");
//       //   break;
//       // } else if (polling == -1) {
//       //   LogError("Poll error, attempting to recv data");
//       // }
//
//       if (SSL_pending(ssl) == 0) {
//         LogError("No more data to read");
//         break;
//       }
//
//       bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);
//       request.append(buffer.data(), bytesReceived);
//     }
//
//     std::cout << "Raw request: " << request << std::endl;
//     bool acceptEncoding = false;
//     if (ValidateRequestsHTTP1(request, method, path, acceptEncoding) ==
//     ERROR) {
//       LogError("Request validation was unsuccessful");
//       continue;
//     }
//
//     if (path.starts_with("/static/")) {
//       std::string filePath = "static" + path.substr(7);
//       // Check how to proceed in here
//       ServerRouter->staticFileHandler(ssl, filePath, acceptEncoding);
//       continue;
//     }
//
//     status = ServerRouter->RouteRequest(method, path, ssl);
//   }
//
//   // Timer should end  here and log it to the file
//
//   auto endTime = std::chrono::high_resolution_clock::now();
//
//   std::chrono::duration<double> elapsed = endTime - startTime;
//
//   // std::cout << "Request handled in " << elapsed.count() << " seconds\n";
//   std::ostringstream logStream;
//   logStream << "Method: " << method << " Path: " << path
//             << " Status: " << status << " Elapsed time: " << elapsed.count()
//             << " s";
//
//   LogRequest(logStream.str());
//
//   SSL_shutdown(ssl);
//   SSL_free(ssl);
//   activeConnections--;
//   close(clientSock);
// }

HTTPServer::~HTTPServer() {
  if (serverSock != -1) {
    close(serverSock);
  }
  LogError("Server shutdown.");
  std::cout << "Server shutdown gracefully" << std::endl;
}

void HTTPServer::AddRoute(const std::string &method, const std::string &path,
                          const ROUTE_HANDLER &handler) {
  ServerRouter->AddRoute(method, path, handler);
}

void HTTPServer::RunHTTP3() {
  // Starts listening for incoming connections.
  if (QUIC_FAILED(Status =
                      MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
    printf("ListenerStart failed, 0x%x!\n", Status);
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }
}

void HTTPServer::Run() {
  // Starts listening for incoming connections.
  // if (QUIC_FAILED(Status =
  //                     MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
  //   printf("ListenerStart failed, 0x%x!\n", Status);
  //   LogError("Server failed to load configuration.");
  //   if (Listener != NULL) {
  //     MsQuic->ListenerClose(Listener);
  //   }
  //   return;
  // }
  //
  std::thread http3Thread(&HTTPServer::RunHTTP3, this);
  http3Thread.detach();
  // HTTPServer::RunHTTP3();
  // Continue listening for connections until the Enter key is pressed.
  while (!shouldShutdown) {
  }
  //
  // printf("Press Enter to exit.\n\n");
  // getchar();
}

void HTTPServer::PrintFromServer() { std::cout << "Hello from server\n"; }

HTTPServer::HTTPServer(int argc, char *argv[])
    : Status(0), activeConnections(0), Listener(nullptr) {
  // Configures the address used for the listener to listen on all IP
  // addresses and the given UDP port.
  Address = {0};
  QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&Address, UDP_PORT);

  // Load the server configuration based on the command line.
  if (!ServerLoadConfiguration(argc, argv)) {
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }

  // Create/allocate a new listener object.
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(
                      Registration, ServerListenerCallback, this, &Listener))) {
    printf("ListenerOpen failed, 0x%x!\n", Status);
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }

  ServerRouter = std::make_unique<Router>();
};

void HTTPServer::Initialize(int argc, char *argv[]) {
  std::lock_guard<std::mutex> lock(instanceMutex); // Ensure thread-safety
  if (!instance) {
    instance = new HTTPServer(argc, argv);
  }
}

HTTPServer *HTTPServer::GetInstance() {
  std::lock_guard<std::mutex> lock(instanceMutex); // Ensure thread-safety
  if (!instance) {
    return nullptr;
  }
  return instance; // Return raw pointer to the instance
}

// if (setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
//                sizeof timeout) == -1) {
//   LogError(threadSafeStrerror(errno));
// }
//
// if (setsockopt(clientSock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
//                sizeof timeout) == -1) {
//   LogError(threadSafeStrerror(errno));
// }

// std::thread([this, clientSock, startTime]() {
//   clientHandlerThread(clientSock, startTime);
// }).detach();
