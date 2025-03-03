#ifndef HTTPBASE_HPP
#define HTTPBASE_HPP

#include <msquic.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "codec.hpp"
#include "framebuilder.hpp"
#include "lshpack.h"
#include "transport.hpp"
#include "utils.hpp"

class HttpCore {
protected:
  // Codec resources
  std::unique_ptr<HpackCodec> hpackCodec;
  std::unique_ptr<QpackCodec> qpackCodec;

  // Frame builder resources
  std::unique_ptr<Http2FrameBuilder> http2FrameBuilder;
  std::unique_ptr<Http3FrameBuilder> http3FrameBuilder;

  // Transport manager resources
  std::unique_ptr<TcpTransport> tcpTransport;
  std::unique_ptr<QuicTransport> quicTransport;

  virtual unsigned char LoadQUICConfiguration(int argc, char *argv[]) = 0;

public:
  /*----------------------------------------------------------*/
  HttpCore();

  void EncodeHPACKHeaders(
      lshpack_enc &encoder,
      const std::unordered_map<std::string, std::string> &headers,
      std::vector<uint8_t> &encodedHeaders);

  void DecodeHPACKHeaders(
      lshpack_dec &decoder, std::vector<uint8_t> &encodedHeaders,
      std::unordered_map<std::string, std::string> &decodedHeaders);

  void EncodeQPACKHeaders(
      HQUIC *stream,
      const std::unordered_map<std::string, std::string> &headers,
      std::vector<uint8_t> &encodedHeaders);

  void DecodeQPACKHeaders(
      HQUIC *stream, std::vector<uint8_t> &encodedHeaders,
      std::unordered_map<std::string, std::string> &decodedHeaders);

  std::vector<uint8_t>
  BuildHttp2Frame(Frame type, uint8_t frameFlags = 0, uint32_t streamId = 0,
                  uint32_t errorCode = 0, uint32_t increment = 0,
                  const std::vector<uint8_t> &encodedHeaders = {},
                  const std::string &data = "");

  std::vector<uint8_t>
  BuildHttp3Frame(Frame type, uint32_t streamOrPushId = 0,
                  const std::vector<uint8_t> &encodedHeaders = {},
                  const std::string &data = "");

  int Send(void *connection, const std::vector<uint8_t> &bytes,
           bool useQuic = false);

  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes,
                bool useQuic = false);

  int Receive(void *connection, std::vector<uint8_t> &buffer,
              uint32_t writeOffset, bool useQuic = false);

  int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
              std::mutex &mut, bool useQuic = false);

  int SendBatch_TS(void *connection,
                   const std::vector<std::vector<uint8_t>> &bytes,
                   std::mutex &mut, bool useQuic = false);

  int Receive_TS(void *connection, std::vector<uint8_t> &buffer,
                 uint32_t writeOffset, std::mutex &mut, bool useQuic = false);

  /*----------------------------------------------------------*/

  int TCP_Socket;
  sockaddr_in TCP_SocketAddress;

  struct addrinfo *TCP_SocketAddr;

  struct timeval timeout;
  SSL_CTX *SSL_ctx;

  std::unordered_map<HQUIC, std::vector<uint8_t>> QuicBufferMap;
  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      QuicDecodedHeadersMap;

  std::unordered_map<SSL *, std::mutex> TCP_MutexMap;

  virtual ~HttpCore() = default;

  int HTTP1_SendFile(SSL *ssl, const std::string &filePath);

  void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
                         std::string &data);

  static void RespHeaderToPseudoHeader(
      const std::string &http1Headers,
      std::unordered_map<std::string, std::string> &headerMap);

  static void ReqHeaderToPseudoHeader(
      const std::string &http1Headers,
      std::unordered_map<std::string, std::string> &headersMap);

  static uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                             const std::vector<uint8_t>::iterator &end);
};

#endif // HTTPBASE_HPP
