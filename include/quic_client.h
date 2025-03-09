#ifndef QUICCLIENT_HPP
#define QUICCLIENT_HPP

#include <netinet/in.h>

#include <memory>

#include "codec.h"
#include "http3_frame_builder.h"
#include "router.h"
#include "transport.h"

// #include "http2_frame_handler.h"

class QuicClient {
 public:
  explicit QuicClient(
      int argc, char *argv[],
      const std::vector<std::pair<std::string, std::string>> &requests);
  ~QuicClient();

  void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &strm_buf,
                         std::string &data);

  void Run(int argc, char *argv[]);

  static void QuicSend(_In_ HQUIC Connection, void *Context);

  const std::vector<std::pair<std::string, std::string>> requests_;

  std::weak_ptr<Router> router_;

  std::shared_ptr<QuicTransport> transport_;

  std::shared_ptr<Http3FrameBuilder> frame_builder_;

  std::shared_ptr<QpackCodec> codec_;

 private:
  static const QUIC_API_TABLE *ms_quic_;

  HQUIC registration_;

  static HQUIC config_;

  static constexpr QUIC_REGISTRATION_CONFIG kRegConfig = {
      "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY};

  QUIC_STATUS status_;

  std::unordered_map<HQUIC, std::vector<uint8_t>> quic_buffer_map_;

  std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
      quic_headers_map_;

  int LoadConfiguration(int argc, char *argv[]);

  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
      static StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                            _Inout_ QUIC_STREAM_EVENT *Event);

  _IRQL_requires_max_(DISPATCH_LEVEL)
      _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
      static ConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                                _Inout_ QUIC_CONNECTION_EVENT *Event);
};

#endif  // QUICCLIENT_HPP
