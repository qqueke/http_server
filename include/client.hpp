#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <atomic>
#include <cstddef>
#include <unordered_map>

#include "common.hpp"
#include "utils.hpp"

class HTTPClient : public HTTPBase {
private:
public:
  HTTPClient(int argc, char *argv[]);
  ~HTTPClient();

  std::atomic<size_t> nRequests;
  // Headers, Body
  std::vector<std::pair<std::string, std::string>> requests;

  void ReceiveHTTP2Responses(SSL *ssl);

  void ParseRequestsFromFile(const std::string &filePath);

  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
      static StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                            _Inout_ QUIC_STREAM_EVENT *Event);

  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
      static ConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                                _Inout_ QUIC_CONNECTION_EVENT *Event);

  void PrintFromServer();
  void Run(int argc, char *argv[]);

  unsigned char LoadQUICConfiguration(int argc, char *argv[]) override;

  void QPACK_DecodeHeaders(HQUIC stream,
                           std::vector<uint8_t> &encodedHeaders) override;

  void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
                         std::string &data) override;

  static int dhiProcessHeader(void *hblock_ctx, struct lsxpack_header *xhdr);
};

#endif
