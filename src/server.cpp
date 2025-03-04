#include "server.hpp"

#include <fcntl.h>
#include <lshpack.h>
#include <msquic.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/poll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <array>
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
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "common.hpp"
#include "framehandler.hpp"
#include "log.hpp"
#include "router.hpp"
#include "tlsmanager.hpp"
#include "utils.hpp"

// #define HTTP2_DEBUG

bool shouldShutdown(false);

// int alpnSelectCallback(SSL *ssl, const unsigned char **out,
//                        unsigned char *outlen, const unsigned char *in,
//                        unsigned int inlen, void *arg) {
//   static constexpr std::array<std::string, 2> serverProtocols = {"h2",
//                                                                  "http/1.1"};
//
//   std::unordered_set<std::string> clientProtocols;
//
//   for (size_t i = 0; i < inlen;) {
//     unsigned char len = in[i];
//     clientProtocols.insert(
//         std::string(reinterpret_cast<const char *>(&in[i + 1]), len));
//     i += len + 1;
//   }
//
//   for (const auto &serverProtocol : serverProtocols) {
//     if (clientProtocols.find(serverProtocol) != clientProtocols.end()) {
//       *out = (const unsigned char *)(serverProtocol.c_str());
//       *outlen = (unsigned char)(serverProtocol.size());
//       return SSL_TLSEXT_ERR_OK;
//     }
//   }
//
//   return SSL_TLSEXT_ERR_NOACK;
// }

int alpnSelectCallback(SSL *ssl, const unsigned char **out,
                       unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
  static constexpr std::array<unsigned char, 12> AlpnProtos = {
      2, 'h', '2',                              // HTTP/2
      8, 'h', 't', 't', 'p', '/', '1', '.', '1' // HTTP/1.1
  };

  if (SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
                            AlpnProtos.data(),
                            AlpnProtos.size()) == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }

  return SSL_TLSEXT_ERR_NOACK;
}

// std::string Router::StaticFileHandler(const std::string &filePath,
//                                       bool acceptEncoding, Protocol protocol,
//                                       void *context) {
//   std::string headers = "HTTP/1.1 200 OK\r\n";
//
//   uint64_t fileSize = 0;
//   if (acceptEncoding) {
//     struct stat buf{};
//     int error = stat((filePath + ".gz").c_str(), &buf);
//     // File exists
//     if (error == 0) {
//       fileSize = buf.st_size;
//     } else {
//       fileSize = CompressFile(filePath, filePath + ".gz", GZIP);
//     }
//   }
//
//   if (fileSize != 0) {
//     headers += "Content-Encoding: gzip\r\n";
//     headers += "Content-Length: " + std::to_string(fileSize) + "\r\n\r\n";
//   }
//
//   static constexpr std::string_view altSvcHeader =
//       "Alt-Svc: h3=\":4567\"; ma=86400\r\n";
//
//   switch (protocol) {
//   case Protocol::HTTP1:
//
//   {
//     size_t headerEnd = headers.find("\r\n\r\n");
//     if (headerEnd != std::string::npos) {
//       headers.insert(headerEnd + 2, altSvcHeader);
//     }
//
//     std::string response = headers + body;
//     SSL *clientSSL = (SSL *)context;
//
//     sendFile(clientSSL, filePath, acceptEncoding);
//     HttpCore::HTTP1_SendMessage(clientSSL, response);
//   }
//
//   break;
//   case Protocol::HTTP2:
//
//   {
//     HTTP2Context *ctx = (HTTP2Context *)context;
//
//     SSL *clientSSL = ctx->ssl;
//     struct lshpack_enc *enc = ctx->enc;
//     uint32_t streamId = ctx->streamId;
//
//     std::unordered_map<std::string, std::string> headersMap;
//
//     headersMap.reserve(2);
//
//     HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
//
//     headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";
//
//     std::vector<uint8_t> headerFrame(256);
//
//     HttpCore::HPACK_EncodeHeaderIntoFrame(*enc, headersMap, headerFrame);
//
//     std::vector<std::vector<uint8_t>> frames;
//
//     frames.reserve(2);
//
//     HttpCore::HTTP2_FillHeaderFrame(headerFrame, streamId);
//
//     frames.emplace_back(std::move(headerFrame));
//
//     frames.emplace_back(
//         std::move(HttpCore::HTTP2_BuildDataFrame(body, streamId)));
//
//     HttpCore::HTTP2_SendFrames(clientSSL, frames);
//   }
//
//   break;
//
//   case Protocol::HTTP3:
//
//   {
//     HQUIC Stream = (HQUIC)context;
//     std::unordered_map<std::string, std::string> headersMap;
//     headersMap.reserve(2);
//
//     HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
//
//     std::vector<uint8_t> encodedHeaders;
//
//     uint64_t streamId{};
//     uint32_t len = (uint32_t)sizeof(streamId);
//     if (QUIC_FAILED(
//             MsQuic->GetParam(Stream, QUIC_PARAM_STREAM_ID, &len, &streamId)))
//             {
//       LogError("Failed to acquire stream id");
//     }
//
//     HttpCore::QPACK_EncodeHeaders(streamId, headersMap, encodedHeaders);
//
//     std::vector<std::vector<uint8_t>> frames;
//     frames.reserve(2);
//
//     frames.emplace_back(HttpCore::HTTP3_BuildHeaderFrame(encodedHeaders));
//
//     frames.emplace_back(HttpCore::HTTP3_BuildDataFrame(body));
//
//     HttpCore::HTTP3_SendFrames(Stream, frames);
//   }
//
//   break;
//   default:
//     LogError("Unknown Protocol");
//     break;
//   }
// }

unsigned char HttpServer::LoadQUICConfiguration(
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

  // Leaks here
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

std::string HttpServer::threadSafeStrerror(int errnum) {
  std::lock_guard<std::mutex> lock(strerrorMutex);
  return {strerror(errnum)};
}

void HttpServer::staticFileHandler(SSL *clientSSL, const std::string &filePath,
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
    if (CompressFile(filePath, filePath + ".gz", GZIP)) {
      sendFile(clientSSL, filePath + ".gz", acceptEncoding);
      return;
    }

    LogError("Compression failed, falling back to full file");
  }

  sendFile(clientSSL, filePath, acceptEncoding);
}

void HttpServer::ValidateHeaders(const std::string &request,
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

void HttpServer::ValidatePseudoHeaders(
    std::unordered_map<std::string, std::string> &headersMap) {
  static constexpr std::array<std::string_view, 3> requiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : requiredHeaders) {
    if (headersMap.find(std::string(header)) == headersMap.end()) {
      // LogError("Failed to validate pseudo-headers (missing header field)");
      headersMap[":method"] = "BR";
      headersMap[":path"] = "";
      return;
    }
  }
}

void Test(void *context) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  uint8_t &num3 = frameContext.num;
  ++num3;
}

void HttpServer::HandleHTTP2Request(SSL *ssl) {
  static constexpr std::array<uint8_t, 24> HTTP2_PrefaceBytes = {
      0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32,
      0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A};

  std::vector<uint8_t> buffer;
  buffer.reserve(65535);

  struct lshpack_dec dec{};
  lshpack_dec_init(&dec);

  struct lshpack_enc enc{};
  lshpack_enc_init(&enc);

  auto startTime = std::chrono::high_resolution_clock::now();

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      TcpDecodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> TcpDataMap;

  uint8_t num = 1;
  bool expectingContFrame = false;
  bool goAway = false;
  Http2FrameContext context(TcpDecodedHeadersMap, EncodedHeadersBufferMap,
                            TcpDataMap, enc, dec, num, goAway,
                            expectingContFrame);

  // Test(&context);
  // std::cout << "After test: " << (int)num << std::endl;

  // std::string auto [headers, body]{};

  uint32_t connectionWindowSize{};
  std::unordered_map<uint32_t, uint32_t> streamWindowSizeMap;

  // Change this to bitset

  bool receivedPreface = false;

  uint32_t nRequests = 0;

  int readOffset = 0;
  int writeOffset = 0;
  int bytesReceived = 0;
  size_t nReadableBytes = 0;

  // TODO: implement circular buffer

  while (!shouldShutdown && !goAway) {
    bytesReceived = Receive(ssl, buffer, writeOffset);
    if (bytesReceived == ERROR) {
      break;
    }

    writeOffset += bytesReceived;
    nReadableBytes += (size_t)bytesReceived;

    if (!receivedPreface) {
      if (nReadableBytes < PREFACE_LENGTH) {
        continue;
      }

      if (memcmp(HTTP2_PrefaceBytes.data(), buffer.data(), PREFACE_LENGTH) !=
          0) {
        LogError("Invalid HTTP/2 preface, closing connection.");
        break;
      }

#ifdef HTTP2_DEBUG
      std::cout << "HTTP/2 Connection Preface received!\n";
#endif

      Send(ssl, BuildHttp2Frame(Frame::SETTINGS));

      receivedPreface = true;
      readOffset = PREFACE_LENGTH;
      nReadableBytes -= PREFACE_LENGTH;
    }

    // If we received atleast the frame header
    while (FRAME_HEADER_LENGTH <= nReadableBytes && !goAway) {
      uint8_t *framePtr = buffer.data() + readOffset;

      uint32_t payloadLength = (static_cast<uint32_t>(framePtr[0]) << 16) |
                               (static_cast<uint32_t>(framePtr[1]) << 8) |
                               static_cast<uint32_t>(framePtr[2]);

      if (payloadLength > MAX_PAYLOAD_FRAME_SIZE) {
        goAway = true;
        Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                  HTTP2ErrorCode::FRAME_SIZE_ERROR));
        break;
      }

      uint8_t frameType = framePtr[3];

      uint8_t frameFlags = framePtr[4];

      uint32_t frameStream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                             (framePtr[7] << 8) | framePtr[8];

      if (expectingContFrame && frameType != Frame::CONTINUATION) {
        goAway = true;

        Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                  HTTP2ErrorCode::PROTOCOL_ERROR));
        break;
      }

      int ret = http2FrameHandler->ProcessFrame(&context, frameType,
                                                frameStream, buffer, readOffset,
                                                payloadLength, frameFlags, ssl);

      if (ret == ERROR) {
        break;
      }

      // Move the offset to the next frame
      readOffset += (int)FRAME_HEADER_LENGTH + payloadLength;

      // Decrement readably bytes by the current frame size
      nReadableBytes -= (size_t)FRAME_HEADER_LENGTH + payloadLength;
    }

    if (nReadableBytes == 0) {
      writeOffset = 0;
      readOffset = 0;
    }
  }

  lshpack_enc_cleanup(&enc);
  lshpack_dec_cleanup(&dec);

  // Timer should end  here and log it to the file
  // auto endTime = std::chrono::high_resolution_clock::now();

  // std::chrono::duration<double> elapsed = endTime - startTime;

  // std::cout << "Elapsed time: " << elapsed.count() << " s" << std::endl;

  // std::ostringstream logStream;
  // logStream << "Protocol: HTTP2 "
  //           << "Method: " << method << " Path: " << path
  //           << " Status: " << status << " Elapsed time: " << elapsed.count()
  //           << " s";
  //
  // LogRequest(logStream.str());
}

void HttpServer::HandleHTTP1Request(SSL *ssl) {
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

    auto [headers, resBody] = router->RouteRequest(method, path, body);

    static constexpr std::string_view altSvcHeader =
        "Alt-Svc: h3=\":4567\"; ma=86400\r\n";

    size_t headerEnd = headers.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
      headers.insert(headerEnd + 2, altSvcHeader);
    }

    std::string response = headers + resBody;

    std::vector<uint8_t> responseBytes(response.begin(), response.end());
    Send(ssl, responseBytes);
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

void HttpServer::RequestThreadHandler(int clientSocket) {
  // Create SSL object
  SSL *ssl = tlsManager->CreateSSL(clientSocket);
  if (ssl == nullptr) {
    return;
  }

  int ret = tlsManager->Handshake(ssl, clientSocket);
  if (ret == ERROR) {
    return;
  }

  std::string_view protocol = tlsManager->GetSelectedProtocol(ssl);
  if (protocol == "h2") {
    HandleHTTP2Request(ssl);
  } else if (protocol == "http/1.1") {
    HandleHTTP1Request(ssl);
  } else {
    LogError("Unsupported protocol or ALPN negotiation failed");
  }

  tlsManager->DeleteSSL(ssl);
  close(clientSocket);
}

HttpServer::~HttpServer() {
  // Wait for TCP thread to close the socket and set it to -1
  while (TCP_Socket != -1) {
  }

  SSL_CTX_free(SSL_ctx);

  std::cout << "Server shutdown gracefully" << std::endl;
}

void HttpServer::AddRoute(const std::string &method, const std::string &path,
                          const ROUTE_HANDLER &handler) {
  router->AddRoute(method, path, handler);
}

void HttpServer::RunTCP() {
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

    // struct sockaddr_storage {
    //     sa_family_t  ss_family;     // address family
    //
    //     // all this is padding, implementation specific, ignore it:
    //     char      __ss_pad1[_SS_PAD1SIZE];
    //     int64_t   __ss_align;
    //     char      __ss_pad2[_SS_PAD2SIZE];
    // };

    struct sockaddr_storage peerAddr;
    socklen_t peerAddrLen = sizeof(peerAddr);

    int clientSocket = accept(TCP_Socket, (sockaddr *)&peerAddr, &peerAddrLen);
    if (clientSocket == -1) {
      LogError(threadSafeStrerror(errno));
      continue;
    }

    if (peerAddr.ss_family == AF_INET) { // IPv4
      sockaddr_in *ipv4 = (struct sockaddr_in *)&peerAddr;
      char ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
      std::cout << "Connection established with IPv4 address: " << ip
                << std::endl;
    } else if (peerAddr.ss_family == AF_INET6) { // IPv6
      sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&peerAddr;
      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
      std::cout << "Connection established with IPv6 address: " << ip
                << std::endl;
    } else {
      std::cout << "Unknown address family: " << peerAddr.ss_family
                << std::endl;
    }

    // Set recv timeout
    timeout.tv_usec = 100 * 1000;

    if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    // Set send timeout
    timeout.tv_usec = 100 * 1000;

    if (setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof timeout) == ERROR) {
    }

    int buffSize = 256 * 1024; // 256 KB
    if (setsockopt(TCP_Socket, SOL_SOCKET, SO_RCVBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    if (setsockopt(TCP_Socket, SOL_SOCKET, SO_SNDBUF, &buffSize,
                   sizeof(buffSize)) == ERROR) {
      LogError(threadSafeStrerror(errno));
    }

    std::thread([this, clientSocket]() {
      RequestThreadHandler(clientSocket);
    }).detach();
  }

  if (TCP_Socket != -1) {
    close(TCP_Socket);
  }

  TCP_Socket = -1;
}

void HttpServer::RunQUIC() {
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

void HttpServer::Run() {
  std::thread quicThread(&HttpServer::RunQUIC, this);
  quicThread.detach();

  RunTCP();
}

void HttpServer::PrintFromServer() { std::cout << "Hello from server\n"; }

HttpServer::HttpServer(int argc, char *argv[]) : Status(0), Listener(nullptr) {
  //------------------------ HTTP/1/2 TCP SETUP----------------------
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  // Unspec was not working for both connections
  // Thus this way, worst case we map IPv4 addr to IPv6
  hints.ai_family = AF_INET6; /*  IPv6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
  hints.ai_protocol = 0;       /* Any protocol */
  // hints.ai_canonname = NULL;
  // hints.ai_addr = NULL;
  // hints.ai_next = NULL;

  std::string port = std::to_string(HTTP_PORT);

  int s = getaddrinfo(NULL, port.c_str(), &hints, &TCP_SocketAddr);
  if (s != 0) {
    LogError("getaddrinfo: " + std::string(gai_strerror(s)));
    exit(EXIT_FAILURE);
  }

  struct addrinfo *addr = nullptr;
  for (addr = TCP_SocketAddr; addr != nullptr; addr = addr->ai_next) {
    TCP_Socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (TCP_Socket == -1) {
      std::cout << "Failed....\n";
      continue;
    }

    if (bind(TCP_Socket, addr->ai_addr, addr->ai_addrlen) == 0) {
      break;
    }

    close(TCP_Socket);
  }

  freeaddrinfo(TCP_SocketAddr);

  if (addr == nullptr) {
    LogError("Could not bind to any address");
    exit(EXIT_FAILURE);
  }

  timeout = {};
  timeout.tv_sec = TIMEOUT_SECONDS;

  int buffSize = 4 * 256 * 1024; // 256 KB
  setsockopt(TCP_Socket, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize));
  setsockopt(TCP_Socket, SOL_SOCKET, SO_SNDBUF, &buffSize, sizeof(buffSize));

  // SSL_load_error_strings();
  // SSL_library_init();
  // OpenSSL_add_all_algorithms();
  router = std::make_unique<Router>();

  http2FrameHandler = std::make_unique<Http2FrameHandler>(this);

  tlsManager = std::make_unique<TlsManager>(TlsMode::SERVER, 10);
  tlsManager->LoadCertificates("certificates/server.crt",
                               "certificates/server.key");

  // OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
  // OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
  //
  // SSL_ctx = SSL_CTX_new(SSLv23_server_method());
  // if (!SSL_ctx) {
  //   LogError("Failed to create SSL context");
  //   exit(EXIT_FAILURE);
  // }
  //
  // if (SSL_CTX_use_certificate_file(SSL_ctx, "certificates/server.crt",
  //                                  SSL_FILETYPE_PEM) <= 0) {
  //   LogError("Failed to load server certificate");
  //   exit(EXIT_FAILURE);
  // }
  //
  // if (SSL_CTX_use_PrivateKey_file(SSL_ctx, "certificates/server.key",
  //                                 SSL_FILETYPE_PEM) <= 0) {
  //   LogError("Failed to load server private key");
  //   exit(EXIT_FAILURE);
  // }
  //
  // if (!SSL_CTX_check_private_key(SSL_ctx)) {
  //   LogError("Private key does not match the certificate");
  //   exit(EXIT_FAILURE);
  // }
  //
  // SSL_CTX_set_alpn_select_cb(SSL_ctx, alpnSelectCallback, NULL);

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
};
