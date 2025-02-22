#include "server.hpp"

#include <lshpack.h>
#include <msquic.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "common.hpp"
#include "log.hpp"
#include "router.hpp"
#include "utils.hpp"

static std::unordered_map<std::string, std::string> responseCache;
static std::mutex responseMutex;
static std::mutex cacheMutex;

bool shouldShutdown(false);

HTTPServer *HTTPServer::instance = nullptr;
std::mutex HTTPServer::instanceMutex;

std::vector<std::string> serverProtocols = {"h2", "http/1.1"};

int alpnSelectCallback(SSL *ssl, const unsigned char **out,
                       unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
  std::unordered_set<std::string> clientProtocols;

  for (size_t i = 0; i < inlen;) {
    unsigned char len = in[i];
    clientProtocols.insert(
        std::string(reinterpret_cast<const char *>(&in[i + 1]), len));
    i += len + 1;
  }

  for (const auto &serverProtocol : serverProtocols) {
    if (clientProtocols.find(serverProtocol) != clientProtocols.end()) {
      *out = (const unsigned char *)(serverProtocol.c_str());
      *outlen = (unsigned char)(serverProtocol.size());
      return SSL_TLSEXT_ERR_OK;
    }
  }

  return SSL_TLSEXT_ERR_NOACK;
}

int HTTPServer::QPACK_ProcessHeader(void *hblock_ctx,
                                    struct lsxpack_header *xhdr) {
  std::string headerKey(xhdr->buf + xhdr->name_offset, xhdr->name_len);
  std::string headerValue(xhdr->buf + xhdr->val_offset, xhdr->val_len);

  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx;
  // block_ctx->stream
  HTTPServer *server = HTTPServer::GetInstance();

  server->QuicDecodedHeadersMap[block_ctx->stream][headerKey] = headerValue;

  return 0;
}

unsigned char HTTPServer::LoadQUICConfiguration(
    _In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[]) {
  QUIC_SETTINGS Settings = {0};

  // Configures the server's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;

  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  Settings.PeerBidiStreamCount = 100;
  Settings.IsSet.PeerBidiStreamCount = TRUE;
  Settings.PeerUnidiStreamCount = 2;
  Settings.IsSet.PeerUnidiStreamCount = TRUE;

  // Settings.StreamMultiReceiveEnabled = TRUE;

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  const char *Cert;
  const char *KeyFile;
  if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
    // Load the server's certificate from the default certificate store,
    // using the provided certificate hash.

    uint32_t CertHashLen = DecodeHexBuffer(
        Cert, sizeof(Config.CertHash.ShaHash), Config.CertHash.ShaHash);
    if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
      return FALSE;
    }
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
    Config.CredConfig.CertificateHash = &Config.CertHash;

  } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
             (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
    // Loads the server's certificate from the file.
    const char *Password = GetValue(argc, argv, "password");
    if (Password != NULL) {
      Config.CertFileProtected.CertificateFile = (char *)Cert;
      Config.CertFileProtected.PrivateKeyFile = (char *)KeyFile;
      Config.CertFileProtected.PrivateKeyPassword = (char *)Password;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
      Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
    } else {
      Config.CertFile.CertificateFile = (char *)Cert;
      Config.CertFile.PrivateKeyFile = (char *)KeyFile;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
      Config.CredConfig.CertificateFile = &Config.CertFile;
    }

  } else {
    printf("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and "
           "optionally 'password')]!\n");
    return FALSE;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    std::ostringstream oss;
    oss << "ConfigurationOpen failed, 0x" << std::hex << Status;
    LogError(oss.str());

    return FALSE;
  }

  // Loads the TLS credential part of the configuration.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig))) {
    std::ostringstream oss;
    oss << "ConfigurationLoadCredential failed, 0x" << std::hex << Status;
    LogError(oss.str());
    return FALSE;
  }

  return TRUE;
}

void HTTPServer::QPACK_DecodeHeaders(HQUIC stream,
                                     std::vector<uint8_t> &encodedHeaders) {
  std::vector<struct lsqpack_dec> dec(1);

  uint64_t streamId{};
  uint32_t len = (uint32_t)sizeof(streamId);
  if (QUIC_FAILED(
          MsQuic->GetParam(stream, QUIC_PARAM_STREAM_ID, &len, &streamId))) {
    LogError("Failed to acquire stream id");
  }

  struct lsqpack_dec_hset_if hset_if;
  hset_if.dhi_unblocked = HTTPBase::dhiUnblocked;
  hset_if.dhi_prepare_decode = HTTPBase::dhiPrepareDecode;
  hset_if.dhi_process_header = QPACK_ProcessHeader;

  enum lsqpack_dec_opts dec_opts {};
  lsqpack_dec_init(dec.data(), NULL, 0x1000, 0, &hset_if, dec_opts);

  // hblock_ctx_t *blockCtx = (hblock_ctx_t *)malloc(sizeof(hblock_ctx_t));

  std::vector<hblock_ctx_t> blockCtx(1);

  memset(&blockCtx.back(), 0, sizeof(hblock_ctx_t));
  blockCtx.back().stream = stream;

  const unsigned char *encodedHeadersPtr = encodedHeaders.data();
  size_t totalHeaderSize = encodedHeaders.size();

  enum lsqpack_read_header_status readStatus;

  readStatus = lsqpack_dec_header_in(dec.data(), &blockCtx.back(), streamId,
                                     totalHeaderSize, &encodedHeadersPtr,
                                     totalHeaderSize, NULL, NULL);

  lsqpack_dec_cleanup(dec.data());
}

void HTTPServer::ParseStreamBuffer(HQUIC Stream,
                                   std::vector<uint8_t> &streamBuffer,
                                   std::string &data) {
  auto iter = streamBuffer.begin();

  while (iter < streamBuffer.end()) {
    // Ensure we have enough data for a frame (frameType + frameLength)
    if (std::distance(iter, streamBuffer.end()) < 3) {
      LogError("Bad frame format (Not enough data)");
      break;
    }

    // Read the frame type
    uint64_t frameType = ReadVarint(iter, streamBuffer.end());

    // Read the frame length
    uint64_t frameLength = ReadVarint(iter, streamBuffer.end());

    // Ensure the payload doesn't exceed the bounds of the buffer
    if (std::distance(iter, streamBuffer.end()) < frameLength) {
      LogError("Payload exceeds buffer bounds");
      break;
    }

    // Handle the frame based on the type
    switch (frameType) {
    case 0x01: // HEADERS frame
      // std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

      {
        std::vector<uint8_t> encodedHeaders(iter, iter + frameLength);

        QPACK_DecodeHeaders(Stream, encodedHeaders);

        // headers = std::string(iter, iter + frameLength);
      }
      break;

    case 0x00: // DATA frame
      // std::cout << "[strm][" << Stream << "] Received DATA frame\n";
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

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < streamBuffer.end()) {
    std::ostringstream oss;
    oss << "Data left to read on Buffer from Stream, 0x" << std::hex << Stream
        << "!";
    LogError(oss.str());

    // std::cout.write(reinterpret_cast<const char *>(&(*iter)),
    //                 streamBuffer.end() - iter);
    // std::cout << std::endl;
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

void HTTPServer::ValidateHeaders(const std::string &request,
                                 std::string &method, std::string &path,
                                 std::string &body, bool &acceptEncoding) {
  std::istringstream requestStream(request);
  std::string line;

  std::getline(requestStream, line);
  std::istringstream requestLine(line);
  std::string protocol;
  requestLine >> method >> path >> protocol;

  if (method != "GET" && method != "POST" && method != "PUT") {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  if (path.empty() || path[0] != '/' || path.find("../") != std::string::npos) {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  if (protocol != "HTTP/1.1" && protocol != "HTTP/2") {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  // header, value
  std::unordered_map<std::string, std::string> headers;
  while (std::getline(requestStream, line) && !line.empty()) {
    if (line.size() == 1) {
      continue;
    }

    auto colonPos = line.find(": ");
    if (colonPos == std::string::npos) {
      LogError("Request validation was unsuccessful");
      method = "BR";
      return;
    }

    std::string key = line.substr(0, colonPos);
    std::string value = line.substr(colonPos + 2);

    headers[key] = value;
  }

  // Validate Headers

  // If we don't  find  host then it is a bad request
  if (headers.find("Host") == headers.end()) {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  // If is a POST and has  no content length it is a bad request
  if (method == "POST" && headers.find("Content-Length") == headers.end()) {
    LogError("Request validation was unsuccessful");
    method = "BR";
    return;
  }

  // Parse Body (if has content-length)
  if (headers.find("Content-Length") != headers.end()) {
    size_t contentLength = std::stoi(headers["Content-Length"]);

    body.resize(contentLength);
    requestStream.read(body.data(), (long)contentLength);

    // If body size  doesnt match the content length defined then bad request
    if (body.size() != contentLength) {
      LogError("Request validation was unsuccessful");
      method = "BR";
      return;
    }
  }

  // Not even bothering with enconding type
  if (headers.find("Accept-Encoding") != headers.end()) {
    acceptEncoding = true;
  }

  // If all validations pass
  std::cout << "Request successfully validated!\n";
}

void HTTPServer::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &headersMap) {
  std::unordered_set<std::string> requiredHeaders = {":method", ":scheme",
                                                     ":path"};

  for (const auto &header : requiredHeaders) {
    if (headersMap.find(header) == headersMap.end()) {
      LogError("Failed to validate pseudo-headers (missing header field)");
      headersMap[":method"] = "BR";
      headersMap[":path"] = "";
      return;
    }
  }

  // If all validations pass
  std::cout << "Request successfully validated pseudo-headers!\n";
}

void HTTPServer::HandleHTTP2Request(SSL *ssl) {
  auto startTime = std::chrono::high_resolution_clock::now();
  std::vector<uint8_t> buffer;
  std::vector<uint8_t> tmpBuffer(16000);

  // Buffer headers?
  std::unordered_map<uint32_t, std::vector<uint8_t>> EncodedHeadersBufferMap;

  std::unordered_map<uint32_t, std::string> TcpDataMap;

  std::string method{};
  std::string path{};
  std::string status{};

  const std::array<uint8_t, 24> HTTP2_PrefaceBytes = {
      0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32,
      0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A};

  bool receivedPreface = false;

  const size_t PREFACE_LENGTH = 24;
  const size_t FRAME_HEADER_LENGTH = 9;
  int offset = 0;

  bool GOAWAY = false;

  const int maxRetries = 5;
  const int retryDelayMs = 10;
  int retryCount = 0;

  size_t nRequests = 0;
  while (!shouldShutdown && !GOAWAY) {
    int bytesReceived = SSL_read(ssl, tmpBuffer.data(), (int)tmpBuffer.size());

    if (bytesReceived == 0) {
      LogError("Client closed the connection");
      std::cout << "Client closed the connection" << std::endl;
      break;
    } else if (bytesReceived < 0) {
      int error = SSL_get_error(ssl, bytesReceived);

      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (retryCount < maxRetries) {
          std::cout << "SSL buffer full or not ready, retrying..." << std::endl;
          retryCount++;
          std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
          continue;
        } else {
          LogError("Max retries reached while trying to receive data");
          std::cout << "Max retries reached while trying to receive data"
                    << std::endl;
          break; // Exit the loop after max retries
        }
      } else {
        unsigned long errCode = ERR_get_error();
        char errorString[120];
        ERR_error_string_n(errCode, errorString, sizeof(errorString));

        // Map SSL error code to a human-readable message
        std::string sslErrorMsg;
        switch (error) {
        case SSL_ERROR_NONE:
          sslErrorMsg = "No error occurred.";
          break;
        case SSL_ERROR_ZERO_RETURN:
          sslErrorMsg = "SSL connection was closed cleanly.";
          break;
        case SSL_ERROR_WANT_X509_LOOKUP:
          sslErrorMsg = "Operation blocked waiting for certificate lookup.";
          break;
        case SSL_ERROR_SYSCALL:
          sslErrorMsg = "System call failure or connection reset. " +
                        std::string(errorString);
          break;
        case SSL_ERROR_SSL:
          sslErrorMsg =
              "Low-level SSL library error. " + std::string(errorString);
          break;
        default:
          sslErrorMsg = "Unknown SSL error. " + std::string(errorString);
          break;
        }

        // Log the error
        LogError("Failed to receive data. (SSL_get_error: " +
                 std::to_string(error) + ")");
        std::cout << "Failed to receive data: " + sslErrorMsg << std::endl;
        break;
      }
    }

    retryCount = 0;
    buffer.insert(buffer.end(), tmpBuffer.begin(),
                  tmpBuffer.begin() + bytesReceived);

    if (!receivedPreface) {
      if (buffer.size() < PREFACE_LENGTH) {
        continue;
      }

      if (memcmp(HTTP2_PrefaceBytes.data(), buffer.data(), 24) != 0) {
        LogError("Invalid HTTP/2 preface, closing connection.");
        std::cout << "Invalid HTTP/2 preface, closing connection." << std::endl;
        continue;
      }

      std::cout << "HTTP/2 Connection Preface received!" << std::endl;
      receivedPreface = true;
      offset = 24;
    }

    // If we received atleast the frame header
    while (offset + FRAME_HEADER_LENGTH <= buffer.size() && !GOAWAY) {
      uint8_t *framePtr = buffer.data() + offset;

      uint32_t payloadLength = (static_cast<uint32_t>(framePtr[0]) << 16) |
                               (static_cast<uint32_t>(framePtr[1]) << 8) |
                               static_cast<uint32_t>(framePtr[2]);

      if (offset + FRAME_HEADER_LENGTH + payloadLength > buffer.size()) {
        break;
      }

      uint8_t frameType = framePtr[3];

      uint8_t frameFlags = framePtr[4];

      uint32_t frameStream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                             (framePtr[7] << 8) | framePtr[8];

      // std::cout << "Payload Length: " << std::dec << (int)payloadLength
      //           << std::hex << ", Flags: " << (int)frameFlags << " ";

      switch (frameType) {
      case 0x00:
        // std::cout << "[strm][" << frameStream << "] DATA frame\n";

        TcpDataMap[frameStream] += std::string(
            reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
            payloadLength);

        std::cout << TcpDataMap[frameStream] << std::endl;

        if (isFlagSet(frameFlags, END_STREAM_FLAG)) {
          HTTPServer::ValidatePseudoHeaders(TcpDecodedHeadersMap[frameStream]);

          HTTP2Context context(ssl, frameStream);
          status = ServerRouter->RouteRequest(
              TcpDecodedHeadersMap[frameStream][":method"],
              TcpDecodedHeadersMap[frameStream][":path"],
              TcpDataMap[frameStream], Protocol::HTTP2, &context);
          ++nRequests;
          TcpDecodedHeadersMap.erase(frameStream);
          EncodedHeadersBufferMap.erase(frameStream);
        }
        break;
      case 0x01:
        // std::cout << "[strm][" << frameStream << "] HEADERS frame\n";

        {
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payloadLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and dispatch request
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);

            HTTPServer::ValidatePseudoHeaders(
                TcpDecodedHeadersMap[frameStream]);

            HTTP2Context context(ssl, frameStream);
            status = ServerRouter->RouteRequest(
                TcpDecodedHeadersMap[frameStream][":method"],
                TcpDecodedHeadersMap[frameStream][":path"],
                TcpDataMap[frameStream], Protocol::HTTP2, &context);

            ++nRequests;
            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);

          } else if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and wait for request body
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);
          }
        }
        break;
      case 0x02:
        // std::cout << "[strm][" << frameStream << "] PRIORITY frame\n";

        break;
      case 0x03:
        // std::cout << "[strm][" << frameStream
        //           << "] Received RST_STREAM frame\n";

        TcpDecodedHeadersMap.erase(frameStream);
        EncodedHeadersBufferMap.erase(frameStream);
        break;

      case 0x04:

        // std::cout << "[strm][" << frameStream << "] SETTINGS frame\n";
        {
          std::vector<uint8_t> frame =
              HTTPBase::HTTP2_BuildSettingsFrame(frameFlags);

          int sentBytes = SSL_write(ssl, frame.data(), (int)frame.size());
          if (sentBytes <= 0) {
            LogError("Failed to send SETTINGS frame");
          }
        }

        break;
      case 0x07:

        std::cout << "[strm][" << frameStream << "] GOAWAY frame\n";
        GOAWAY = true;
        TcpDecodedHeadersMap.erase(frameStream);
        EncodedHeadersBufferMap.erase(frameStream);
        break;

      case 0x08:

        // std::cout << "[strm][" << frameStream << "] WINDOW_UPDATE frame\n";

        break;

      case 0x09:

        // std::cout << "[strm][" << frameStream << "] CONTINUATION frame\n";
        {
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payloadLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and dispatch request
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);

            HTTPServer::ValidatePseudoHeaders(
                TcpDecodedHeadersMap[frameStream]);
            HTTP2Context context(ssl, frameStream);
            status = ServerRouter->RouteRequest(
                TcpDecodedHeadersMap[frameStream][":method"],
                TcpDecodedHeadersMap[frameStream][":path"],
                TcpDataMap[frameStream], Protocol::HTTP2, &context);

            ++nRequests;
            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);
          } else if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and wait for request body
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);
          }
        }
        break;

      default:
        std::cout << "[strm][" << frameStream << "] Unknown frame type: 0x"
                  << std::dec << frameType << std::dec << "\n";
        break;
      }

      // Move the offset to the next frame
      offset += FRAME_HEADER_LENGTH + payloadLength;
    }

    // if (offset == buffer.size()) {
    //   buffer.erase(buffer.begin(), buffer.begin() + offset);
    //   offset = 0;
    // }
  }

  std::cout << "Received: " << nRequests << "\n";
  if (GOAWAY) {
    std::cout << "Left because GOAWAY" << std::endl;
  }
  std::string body;

  // Timer should end  here and log it to the file
  auto endTime = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> elapsed = endTime - startTime;

  std::ostringstream logStream;
  logStream << "Protocol: HTTP2 "
            << "Method: " << method << " Path: " << path
            << " Status: " << status << " Elapsed time: " << elapsed.count()
            << " s";

  LogRequest(logStream.str());
}

void HTTPServer::HandleHTTP1Request(SSL *ssl) {
  auto startTime = std::chrono::high_resolution_clock::now();
  std::array<char, BUFFER_SIZE> buffer{};
  std::string request;

  std::string method{};
  std::string path{};
  std::string status{};

  // Just to not delete the while loop
  bool keepAlive = true;

  while (!shouldShutdown && keepAlive) {
    keepAlive = false;

    ssize_t bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);

    if (bytesReceived == 0) {
      LogError("Client closed the connection");
      break;
    } else if (bytesReceived < 0) {
      LogError("Failed to receive data");
      break;
    }

    request.append(buffer.data(), bytesReceived);

    while (bytesReceived == BUFFER_SIZE && !shouldShutdown) {
      if (SSL_pending(ssl) == 0) {
        LogError("No more data to read");
        break;
      }

      bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);
      request.append(buffer.data(), bytesReceived);
    }

    std::cout << "HTTP1 Request:\n" << request << std::endl;

    std::string body;
    bool acceptEncoding = false;

    ValidateHeaders(request, method, path, body, acceptEncoding);

    status =
        ServerRouter->RouteRequest(method, path, body, Protocol::HTTP1, ssl);
  }

  // Timer should end  here and log it to the file
  auto endTime = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> elapsed = endTime - startTime;

  std::ostringstream logStream;
  logStream << "Protocol: HTTP1 "
            << "Method: " << method << " Path: " << path
            << " Status: " << status << " Elapsed time: " << elapsed.count()
            << " s";

  LogRequest(logStream.str());
}

std::mutex sslMutex;
void HTTPServer::RequestThreadHandler(int clientSock) {
  std::lock_guard<std::mutex> lock(sslMutex);
  // Create SSL object
  SSL *ssl = SSL_new(SSL_ctx);

  //  sets the file descriptor clientSock as the input/output facility for
  // theTLS/SSL
  SSL_set_fd(ssl, clientSock);

  // TLS/SSL handshake
  if (SSL_accept(ssl) <= 0) {
    LogError("SSL handshake failed");
    std::cout << "Handshake failed" << std::endl;
    SSL_free(ssl);
    close(clientSock);
    return;
  }

  if (activeConnections >= MAX_CONNECTIONS) {
    ServerRouter->RouteRequest("BR", "", "", Protocol::HTTP1, ssl);
    LogError("Connections limit exceeded");
    SSL_free(ssl);
    close(clientSock);
    return;
  }

  activeConnections++;

  // Protocol must not be freed
  const unsigned char *protocol = NULL;
  unsigned int protocolLen = 0;
  SSL_get0_alpn_selected(ssl, &protocol, &protocolLen);

  if (protocolLen == 2 && memcmp(protocol, "h2", 2) == 0) {
    std::cout << "Routing to HTTP2" << std::endl;
    HandleHTTP2Request(ssl);
  } else if (protocolLen == 8 && memcmp(protocol, "http/1.1", 8) == 0) {
    HandleHTTP1Request(ssl);
  } else {
    LogError("Unsupported protocol or ALPN negotiation failed");
  }

  // SSL_shutdown(ssl);
  SSL_free(ssl);
  close(clientSock);
  activeConnections--;
}

HTTPServer::~HTTPServer() {
  // if (serverSock != -1) {
  //   close(serverSock);
  // }

  // Wait for TCP thread to close the socket and set it to -1
  while (TCP_Socket != -1) {
  }

  SSL_CTX_free(SSL_ctx);

  LogError("Server shutdown.");
  std::cout << "Server shutdown gracefully" << std::endl;
}

void HTTPServer::AddRoute(const std::string &method, const std::string &path,
                          const ROUTE_HANDLER &handler) {
  ServerRouter->AddRoute(method, path, handler);
}

void HTTPServer::RunTCP() {
  if (listen(TCP_Socket, MAX_PENDING_CONNECTIONS) == ERROR) {
    LogError(threadSafeStrerror(errno));
    return;
  }

  struct pollfd pollFds(TCP_Socket, POLLIN, 0);

  while (!shouldShutdown) {
    int polling = poll(&pollFds, 1, 1 * 1000);
    if (polling == 0) {
      continue;
    } else if (polling == ERROR) {
      LogError("Poll error on main thread");
      continue;
    }

    sockaddr clientAddr{};
    socklen_t len = sizeof(clientAddr);
    int clientSock = accept(TCP_Socket, &clientAddr, &len);
    if (clientSock == -1) {
      LogError(threadSafeStrerror(errno));
      continue;
    }

    // Timer should start here
    if (setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(clientSock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    // RequestThreadHandler(clientSock);

    std::thread([this, clientSock]() {
      RequestThreadHandler(clientSock);
    }).detach();
  }

  if (TCP_Socket != -1) {
    close(TCP_Socket);
  }
  TCP_Socket = -1;
}

void HTTPServer::RunQUIC() {
  // Starts listening for incoming connections.
  if (QUIC_FAILED(Status =
                      MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
    // printf("ListenerStart failed, 0x%x!\n", Status);
    std::ostringstream oss;
    oss << "ListenerStart failed, 0x" << std::hex << Status << "!";
    LogError(oss.str());

    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }
}

void HTTPServer::Run() {
  // std::thread tcpThread(&HTTPServer::RunTCP, this);
  // tcpThread.detach();

  std::thread quicThread(&HTTPServer::RunQUIC, this);
  quicThread.detach();

  RunTCP();

  // while (!shouldShutdown) {
  // }
}

void HTTPServer::PrintFromServer() { std::cout << "Hello from server\n"; }

HTTPServer::HTTPServer(int argc, char *argv[])
    : Status(0), activeConnections(0), Listener(nullptr) {
  //------------------------ HTTP1 TCP SETUP----------------------
  TCP_Socket = socket(AF_INET, SOCK_STREAM, 0);
  TCP_SocketAddr = {};
  timeout = {};

  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  SSL_ctx = SSL_CTX_new(SSLv23_server_method());
  if (!SSL_ctx) {
    LogError("Failed to create SSL context");
    exit(EXIT_FAILURE);
  }
  // SSL_CTX_set_timeout(SSL_ctx, 60);

  // SSL_CTX_set_read_buffer_size(SSL_ctx, 8192);
  // SSL_CTX_set_write_buffer_size(SSL_ctx, 8192);

  if (SSL_CTX_use_certificate_file(SSL_ctx, "certificates/server.crt",
                                   SSL_FILETYPE_PEM) <= 0) {
    LogError("Failed to load server certificate");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(SSL_ctx, "certificates/server.key",
                                  SSL_FILETYPE_PEM) <= 0) {
    LogError("Failed to load server private key");
    exit(EXIT_FAILURE);
  }

  if (!SSL_CTX_check_private_key(SSL_ctx)) {
    LogError("Private key does not match the certificate");
    exit(EXIT_FAILURE);
  }

  const unsigned char alpnProtos[] = {
      2, 'h', '2',                              // HTTP/2 ("h2")
      8, 'h', 't', 't', 'p', '/', '1', '.', '1' // HTTP/1.1 ("http/1.1")
  };

  SSL_CTX_set_alpn_select_cb(SSL_ctx, alpnSelectCallback, NULL);

  if (TCP_Socket == ERROR) {
    LogError(threadSafeStrerror(errno));
    exit(EXIT_FAILURE);
  }

  TCP_SocketAddr.sin_family = AF_INET;
  TCP_SocketAddr.sin_port = htons(HTTP_PORT);
  TCP_SocketAddr.sin_addr.s_addr = INADDR_ANY;

  // For HTTPS since the port is 443 we need higher privileges ( Any port
  // bellow
  // 1024 requires that)
  if (bind(TCP_Socket, (struct sockaddr *)&TCP_SocketAddr,
           sizeof(TCP_SocketAddr)) == ERROR) {
    LogError(threadSafeStrerror(errno));
    exit(EXIT_FAILURE);
  }

  timeout = {};
  timeout.tv_sec = TIMEOUT_SECONDS;

  //------------------------ HTTP3 QUIC SETUP----------------------
  // Configures the address used for the listener to listen on all IP
  // addresses and the given UDP port.
  Address = {0};
  QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&Address, UDP_PORT);

  // Load the server configuration based on the command line.
  if (!LoadQUICConfiguration(argc, argv)) {
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }

  // Create/allocate a new listener object.
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ListenerCallback,
                                                this, &Listener))) {
    LogError(std::format("ListenerStart failed, 0x{:x}!", Status));
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
