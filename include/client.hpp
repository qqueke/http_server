#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <atomic>
#include <cstddef>
#include <unordered_map>

#include "common.hpp"
#include "utils.hpp"

class HttpClient : public HttpCore {
private:
public:
  HttpClient(int argc, char *argv[]);
  ~HttpClient();

  // std::unordered_map<SSL *, std::mutex> TCP_MutexMap;

  // Headers, Body
  std::vector<std::pair<std::string, std::string>> requests;

  // void ReceiveHTTP2Responses(SSL *ssl);

  void ParseRequestsFromFile(const std::string &filePath);

  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
      static StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                            _Inout_ QUIC_STREAM_EVENT *Event);

  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
      static ConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                                _Inout_ QUIC_CONNECTION_EVENT *Event);

  void HTTP2_RecvFrames_TS(SSL *ssl);

  void PrintFromServer();

  void RunTCP(int argc, char *argv[]);

  void SendHTTP1Request(SSL *ssl);

  void SendHTTP2Request(SSL *ssl);

  void Run(int argc, char *argv[]);

  unsigned char LoadQUICConfiguration(int argc, char *argv[]);
};

#endif
