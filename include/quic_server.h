#ifndef QUICSERVER_HPP
#define QUICSERVER_HPP

#include <netinet/in.h>

#include <memory>

#include "codec.h"
#include "http3_frame_builder.h"
#include "router.h"
#include "static_content_handler.h"
#include "transport.h"

// #include "http2_frame_handler.h"

class QuicServer {
public:
  explicit QuicServer(
      const std::shared_ptr<Router> &router,
      const std::shared_ptr<StaticContentHandler> &content_handler, int argc,
      char *argv[]);
  ~QuicServer();

  void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &strm_buf,
                         std::string &data);

  void Run();

  std::weak_ptr<Router> router_;

  std::shared_ptr<QuicTransport> transport_;

  std::shared_ptr<Http3FrameBuilder> frame_builder_;

  std::shared_ptr<QpackCodec> codec_;

  std::weak_ptr<StaticContentHandler> static_content_handler_;

private:
  static const QUIC_API_TABLE *ms_quic_;

  HQUIC registration_;

  static HQUIC config_;

  static constexpr QUIC_REGISTRATION_CONFIG kRegConfig = {
      "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY};

  QUIC_STATUS status_;

  HQUIC listener_;

  QUIC_ADDR listen_addr_;

  std::unordered_map<HQUIC, std::vector<uint8_t>> quic_buffer_map_;

  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      quic_headers_map_;

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
};

#endif // QUICSERVER_HPP
