#ifndef HTTPBASE_HPP
#define HTTPBASE_HPP

#include <msquic.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

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

  virtual void DecQPACKHeaders(HQUIC stream,
                               std::vector<uint8_t> &encodedHeaders) = 0;

  virtual void ParseStreamBuffer(HQUIC Stream,
                                 std::vector<uint8_t> &streamBuffer,
                                 std::string &data) = 0;

public:
  std::unordered_map<HQUIC, std::vector<uint8_t>> BufferMap;
  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      DecodedHeadersMap;

  virtual ~HTTPBase() = default;

  // Common functions
  static void dhiUnblocked(void *hblock_ctx);

  static struct lsxpack_header *dhiPrepareDecode(void *hblock_ctx_p,
                                                 struct lsxpack_header *xhdr,
                                                 size_t space);

  static void ResponseHTTP1ToHTTP3Headers(
      const std::string &http1Headers,
      std::unordered_map<std::string, std::string> &headerMap);

  static void RequestHTTP1ToHTTP3Headers(
      const std::string &http1Headers,
      std::unordered_map<std::string, std::string> &headersMap);

  static int
  SendFramesToStream(HQUIC Stream,
                     const std::vector<std::vector<uint8_t>> &frames);
  static int
  SendFramesToNewConn(HQUIC Connection, HQUIC Stream,
                      const std::vector<std::vector<uint8_t>> &frames);

  static std::vector<uint8_t> BuildDataFrame(std::string &data);

  static std::vector<uint8_t>
  BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders);

  static uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                             const std::vector<uint8_t>::iterator &end);
  static void EncodeVarint(std::vector<uint8_t> &buffer, uint64_t value);

  static void
  EncQPACKHeaders(std::unordered_map<std::string, std::string> &headersMap,
                  std::vector<uint8_t> &encodedHeaders);
};

#endif // HTTPBASE_HPP
