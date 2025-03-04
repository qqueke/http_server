
#ifndef HTTPSERVER_HPP
#define HTTPSERVER_HPP

#include <msquic.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

#include "common.hpp"
#include "framehandler.hpp"
#include "router.hpp"
#include "tlsmanager.hpp"

class Http2FrameHandler;

class HttpServer : public HttpCore {
private:
  std::unique_ptr<TlsManager> tlsManager;
  std::unique_ptr<Http2FrameHandler> http2FrameHandler;

  std::mutex strerrorMutex;

  // QUIC stuff
  QUIC_STATUS Status;
  HQUIC Listener;
  QUIC_ADDR Address;

  std::string threadSafeStrerror(int errnum);

  void HandleHTTP1Request(SSL *clientSSL);

  void HandleHTTP2Request(SSL *clientSSL);

  void HandleDataFrame(uint32_t frameStream, const uint8_t *framePtr,
                       uint32_t payloadLength, uint8_t frameFlags, SSL *ssl);

  void RequestThreadHandler(int clientSock);

  void RunTCP();
  void RunQUIC();

  std::unordered_map<HQUIC, std::vector<uint8_t>> ConnectionSettings;

public:
  HttpServer(int argc, char *argv[]);

  HttpServer(const HttpServer &) = delete;
  HttpServer(HttpServer &&) = delete;
  HttpServer &operator=(const HttpServer &) = delete;
  HttpServer &operator=(HttpServer &&) = delete;
  ~HttpServer();

  std::unique_ptr<Router> router;
  // int SendHttp2Response(std::string &headers, std::string &body);

  static int QPACK_ProcessHeader(void *hblock_ctx, struct lsxpack_header *xhdr);

  // The server's callback for stream events from MsQuic.
  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
      static StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                            _Inout_ QUIC_STREAM_EVENT *Event);

  // The server's callback for connection events from MsQuic.
  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
      static ConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                                _Inout_ QUIC_CONNECTION_EVENT *Event);

  // The server's callback for listener events from MsQuic.
  _IRQL_requires_max_(PASSIVE_LEVEL)
      _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
      static ListenerCallback(_In_ HQUIC Listener, _In_opt_ void *Context,
                              _Inout_ QUIC_LISTENER_EVENT *Event);

  /*------------PURE VIRTUAL FUNCTIONS -----------------------*/
  unsigned char LoadQUICConfiguration(
      _In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[]) override;

  /*-------------------------------------------*/

  void staticFileHandler(SSL *clientSSL, const std::string &filePath,
                         bool acceptEncoding);

  static void storeInCache(const std::string &cacheKey,
                           const std::string &response);

  void PrintFromServer();
  void AddRoute(const std::string &method, const std::string &path,
                const ROUTE_HANDLER &handler);
  void Run();

  static void ValidateHeaders(const std::string &request, std::string &method,
                              std::string &path, std::string &body,
                              bool &acceptEncoding);

  void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &headersMap);
};

#endif // HTTPSERVER_HPP
