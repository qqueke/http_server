#ifndef QUICSERVER_HPP
#define QUICSERVER_HPP

#include <netinet/in.h>

#include <memory>

#include "framehandler.hpp"

class QuicServer {
private:
  // std::weak_ptr<HttpServer> server;
  // std::unique_ptr<TlsManager> tlsManager;
  // std::unique_ptr<Http2ServerFrameHandler> http2FrameHandler;

  std::weak_ptr<Router> router;

  std::shared_ptr<QuicTransport> transport;

  std::shared_ptr<Http3FrameBuilder> frameBuilder;

  std::shared_ptr<QpackCodec> codec;

  QUIC_STATUS Status;

  HQUIC Listener;

  QUIC_ADDR Address;

  std::unordered_map<HQUIC, std::vector<uint8_t>> QuicBufferMap;

  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      QuicDecodedHeadersMap;

  int LoadConfiguration(int argc, char *argv[]);

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

public:
  explicit QuicServer(const std::shared_ptr<Router> &router, int argc,
                      char *argv[]);
  ~QuicServer();

  void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
                         std::string &data);

  void Run();
};

#endif // QUICSERVER_HPP
