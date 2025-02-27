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

struct PairHash {
  template <typename T, typename U>
  std::size_t operator()(const std::pair<T, U> &p) const {
    auto h1 = std::hash<T>{}(p.first);  // Hash the first element of the pair
    auto h2 = std::hash<U>{}(p.second); // Hash the second element of the pair

    // Combine the hashes in a way that is less likely to cause collisions
    return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
    // `0x9e3779b9` is a constant (related to the golden ratio) commonly used in
    // hash combinations.
  }
};

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

  virtual void ParseStreamBuffer(HQUIC Stream,
                                 std::vector<uint8_t> &streamBuffer,
                                 std::string &data) = 0;

public:
  int TCP_Socket;
  sockaddr_in TCP_SocketAddress;

  struct addrinfo *TCP_SocketAddr;

  struct timeval timeout;
  SSL_CTX *SSL_ctx;

  std::unordered_map<HQUIC, std::vector<uint8_t>> QuicBufferMap;
  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      QuicDecodedHeadersMap;

  std::unordered_map<SSL *, std::mutex> TCP_MutexMap;

  static void HPACK_EncodeHeaders(
      struct lshpack_enc &enc,
      const std::unordered_map<std::string, std::string> &headersMap,
      std::vector<uint8_t> &encodedHeaders);

  virtual ~HTTPBase() = default;

  static void HPACK_DecodeHeaders(
      struct lshpack_dec &dec,
      std::unordered_map<std::string, std::string> &TcpDecodedHeaders,
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

  static void HTTP2_FillGoAwayFrame(std::vector<uint8_t> &frame,
                                    uint32_t streamId, uint32_t errorCode);

  static void HTTP2_FillSettingsFrame(std::vector<uint8_t> &frame,
                                      uint8_t frameFlags);

  static void HTTP2_FillWindowUpdateFrame(std::vector<uint8_t> &frame,
                                          uint32_t streamId,
                                          uint32_t increment);

  static std::vector<uint8_t>
  HTTP3_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders);

  static std::vector<uint8_t> HTTP2_BuildDataFrame(const std::string &data,
                                                   uint32_t streamID);

  static void HTTP2_FillHeaderFrame(std::vector<uint8_t> &frame,
                                    uint32_t streamId);

  static std::vector<uint8_t>
  HTTP2_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders,
                         uint32_t streamID);

  static void HTTP2_FillRstStreamFrame(std::vector<uint8_t> &frame,
                                       uint32_t streamId, uint32_t errorCode);

  static int HTTP1_SendMessage(SSL *ssl, const std::string &response);

  static int HTTP2_SendFrames(SSL *ssl,
                              std::vector<std::vector<uint8_t>> &frames);

  static int HTTP2_SendFrame(SSL *clientSSL, std::vector<uint8_t> &frame);

  // Thread safe requires instance mutex

  int HTTP2_SendFrame_TS(SSL *ssl, std::vector<uint8_t> &frame);

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

  static void HPACK_EncodeHeaderIntoFrame(
      struct lshpack_enc &enc,
      const std::unordered_map<std::string, std::string> &headersMap,
      std::vector<uint8_t> &frame);
};

#endif // HTTPBASE_HPP
