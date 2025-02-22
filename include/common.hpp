#ifndef HTTPBASE_HPP
#define HTTPBASE_HPP

#include <msquic.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "lshpack.h"

// #include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
// #include "msquic.h"
class HTTPBase {
protected:
  /*--------------------------------------------------------------------*/
  /*--------------------QUIC Callback functions-------------------------*/
  /*--------------------------------------------------------------------*/
  // virtual QUIC_STATUS StreamCallback(_In_ HQUIC Stream, _In_opt_ void
  // *Context,
  //                                    _Inout_ QUIC_STREAM_EVENT *Event) = 0;
  // virtual QUIC_STATUS
  // ConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
  //                    _Inout_ QUIC_CONNECTION_EVENT *Event) = 0;
  //
  // virtual QUIC_STATUS ListenerCallback(_In_ HQUIC Listener,
  //                                      _In_opt_ void *Context,
  //                                      _Inout_ QUIC_LISTENER_EVENT *Event) =
  //                                      0;

  /*--------------------------------------------------------------------*/
  virtual unsigned char LoadQUICConfiguration(int argc, char *argv[]) = 0;

  // Define virtual for run

  virtual void QPACK_DecodeHeaders(HQUIC stream,
                                   std::vector<uint8_t> &encodedHeaders) = 0;

  // virtual void HPACK_DecodeHeaders(uint32_t streamId,
  //                                  std::vector<uint8_t> &encodedHeaders) = 0;

  virtual void ParseStreamBuffer(HQUIC Stream,
                                 std::vector<uint8_t> &streamBuffer,
                                 std::string &data) = 0;

public:
  int TCP_Socket;
  sockaddr_in TCP_SocketAddr;
  struct timeval timeout;
  SSL_CTX *SSL_ctx;

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      TcpDecodedHeadersMap;

  std::unordered_map<HQUIC, std::vector<uint8_t>> QuicBufferMap;
  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      QuicDecodedHeadersMap;

  std::unordered_map<SSL *, std::mutex> TCP_MutexMap;

  struct lshpack_enc enc;

  struct lshpack_dec dec{};

  virtual ~HTTPBase() = default;

  void HPACK_DecodeHeaders2(uint32_t streamId,
                            std::vector<uint8_t> &encodedHeaders);

  // Common functions
  static void dhiUnblocked(void *hblock_ctx);

  static struct lsxpack_header *dhiPrepareDecode(void *hblock_ctx_p,
                                                 struct lsxpack_header *xhdr,
                                                 size_t space);

  static void RespHeaderToPseudoHeader(
      const std::string &http1Headers,
      std::unordered_map<std::string, std::string> &headerMap);

  static void ReqHeaderToPseudoHeader(
      const std::string &http1Headers,
      std::unordered_map<std::string, std::string> &headersMap);

  static int
  HTTP3_SendFramesToStream(HQUIC Stream,
                           const std::vector<std::vector<uint8_t>> &frames);
  static int
  HTTP3_SendFramesToNewConn(HQUIC Connection, HQUIC Stream,
                            const std::vector<std::vector<uint8_t>> &frames);

  static std::vector<uint8_t> HTTP3_BuildDataFrame(const std::string &data);

  static std::vector<uint8_t> HTTP2_BuildGoAwayFrame(uint32_t streamId,
                                                     uint32_t errorCode);
  static std::vector<uint8_t>
  HTTP3_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders);

  static std::vector<uint8_t> HTTP2_BuildDataFrame(const std::string &data,
                                                   uint32_t streamID);

  std::vector<uint8_t> HTTP2_BuildSettingsFrame(uint8_t frameFlags);

  static std::vector<uint8_t>
  HTTP2_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders,
                         uint32_t streamID);

  static int HTTP1_SendMessage(SSL *ssl, const std::string &response);

  static int HTTP2_SendFrames(SSL *ssl,
                              std::vector<std::vector<uint8_t>> &frames);

  // Thread safe requires instance mutex
  int HTTP2_SendFrames_TS(SSL *ssl, std::vector<std::vector<uint8_t>> &frames);

  static int HTTP3_SendFrames(HQUIC Stream,
                              std::vector<std::vector<uint8_t>> &frames);

  /*----------------QPACK helper functions-------------------------*/
  static uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                             const std::vector<uint8_t>::iterator &end);
  static void EncodeVarint(std::vector<uint8_t> &buffer, uint64_t value);

  /*------------- Encoding and Decoding functions------------------*/
  static void
  QPACK_EncodeHeaders(uint64_t streamId,
                      std::unordered_map<std::string, std::string> &headersMap,
                      std::vector<uint8_t> &encodedHeaders);
  static void
  HPACK_EncodeHeaders(std::unordered_map<std::string, std::string> &headersMap,
                      std::vector<uint8_t> &encodedHeaders);

  void
  HPACK_EncodeHeaders2(std::unordered_map<std::string, std::string> &headersMap,
                       std::vector<uint8_t> &encodedHeaders);

  void HPACK_DecodeHeaders(uint32_t streamId,
                           std::vector<uint8_t> &encodedHeaders);
};

#endif // HTTPBASE_HPP
