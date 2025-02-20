
#ifndef HTTPSERVER_HPP
#define HTTPSERVER_HPP

#include <msquic.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "common.hpp"
#include "router.hpp"

class HTTPServer : public HTTPBase {
private:
  static HTTPServer *instance;
  static std::mutex instanceMutex;

  std::mutex strerrorMutex;

  std::atomic<int> activeConnections;

  // TCP stuff
  int serverSock;
  sockaddr_in serverAddr;
  struct timeval timeout;
  SSL_CTX *ctx;

  // QUIC stuff
  QUIC_STATUS Status;
  HQUIC Listener;
  QUIC_ADDR Address;

  std::string threadSafeStrerror(int errnum);

  HTTPServer(int argc, char *argv[]);

  void HandleHTTP1Request(SSL *clientSSL);

  void HandleHTTP2Request(SSL *clientSSL);

  void RequestThreadHandler(int clientSock);

  void RunTCP();
  void RunQUIC();

  std::unordered_map<HQUIC, std::vector<uint8_t>> ConnectionSettings;

public:
  static void Initialize(int argc, char *argv[]);
  static HTTPServer *GetInstance();

  std::unique_ptr<Router> ServerRouter;

  HTTPServer(const HTTPServer &) = delete;
  HTTPServer(HTTPServer &&) = delete;
  HTTPServer &operator=(const HTTPServer &) = delete;
  HTTPServer &operator=(HTTPServer &&) = delete;
  ~HTTPServer();

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
  // Using context to send HTTPServer instance
  _IRQL_requires_max_(PASSIVE_LEVEL)
      _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
      static ListenerCallback(_In_ HQUIC Listener, _In_opt_ void *Context,
                              _Inout_ QUIC_LISTENER_EVENT *Event);

  /*------------PURE VIRTUAL FUNCTIONS -----------------------*/
  unsigned char LoadQUICConfiguration(
      _In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[]) override;

  void QPACK_DecodeHeaders(HQUIC stream,
                           std::vector<uint8_t> &encodedHeaders) override;

  void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
                         std::string &data) override;

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

  static void ValidatePseudoHeaders(
      std::unordered_map<std::string, std::string> &headersMap);

  static int SendHTTP1Response(SSL *clientSSL, const std::string &response);

  static int SendHTTP2Response(SSL *clientSSL,
                               std::vector<std::vector<uint8_t>> &frames);

  static int SendHTTP3Response(HQUIC Stream,
                               std::vector<std::vector<uint8_t>> &frames);
};

#endif // HTTPSERVER_HPP
