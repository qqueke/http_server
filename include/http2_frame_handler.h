#ifndef HTTP2_FRAME_HANDLER
#define HTTP2_FRAME_HANDLER

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "codec.h"
#include "crypto.h"
#include "header_parser.h"
#include "http2_frame_builder.h"
#include "lshpack.h"
#include "router.h"
#include "static_content_handler.h"
#include "transport.h"

class IHttp2FrameHandler {
 public:
  virtual ~IHttp2FrameHandler() = default;
  // virtual ~IHttp2FrameHandler() = default;
  virtual int ProcessFrame(void *context, uint8_t frame_type,
                           uint32_t frame_stream, uint32_t read_offset,
                           uint32_t payload_size, uint8_t frame_flags,
                           SSL *ssl) = 0;

 private:
  virtual int HandleDataFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandleHeadersFrame(void *context, uint32_t frame_stream,
                                 uint32_t read_offset, uint32_t payload_size,
                                 uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandlePriorityFrame(void *context, uint32_t frame_stream,
                                  uint32_t read_offset, uint32_t payload_size,
                                  uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                                   uint32_t read_offset, uint32_t payload_size,
                                   uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandleSettingsFrame(void *context, uint32_t frame_stream,
                                  uint32_t read_offset, uint32_t payload_size,
                                  uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandlePingFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                                uint32_t read_offset, uint32_t payload_size,
                                uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                                      uint32_t read_offset,
                                      uint32_t payload_size,
                                      uint8_t frame_flags, SSL *ssl) = 0;

  virtual int HandleContinuationFrame(void *context, uint32_t frame_stream,
                                      uint32_t read_offset,
                                      uint32_t payload_size,
                                      uint8_t frame_flags, SSL *ssl) = 0;
};

class Http2FrameHandler : IHttp2FrameHandler {
 public:
  // Server constructor
  explicit Http2FrameHandler(const std::vector<uint8_t> &read_buf,
                             bool is_server);

  explicit Http2FrameHandler(
      const std::vector<uint8_t> &read_buf,
      const std::shared_ptr<TcpTransport> &transport,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder,
      const std::shared_ptr<HpackCodec> &hpack_codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr);

  ~Http2FrameHandler();

  int ProcessFrame(void *context, uint8_t frame_type, uint32_t frame_stream,
                   uint32_t read_offset, uint32_t payload_size,
                   uint8_t frame_flags, SSL *ssl) override;

  int ProcessFrame_TS(void *context, uint8_t frame_type, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut);

 private:
  void InitializeSharedResources(
      const std::shared_ptr<TcpTransport> &transport,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder,
      const std::shared_ptr<HpackCodec> &hpack_codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr);

  static bool static_init_;

  static std::weak_ptr<Router> router_;

  static std::weak_ptr<StaticContentHandler> static_content_handler_;

  static std::weak_ptr<TcpTransport> transport_;

  static std::weak_ptr<Http2FrameBuilder> frame_builder_;

  static std::weak_ptr<HpackCodec> codec_;

  static HeaderParser header_parser_;

  const std::vector<uint8_t> &read_buf;

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      tcp_decoded_headers_map_;

  std::unordered_map<uint32_t, std::vector<uint8_t>> encoded_headers_buf_map_;

  std::unordered_map<uint32_t, std::string> tcp_data_map_;

  struct lshpack_enc enc_;

  struct lshpack_dec dec_;

  uint32_t conn_win_size_;

  std::unordered_map<uint32_t, uint32_t> strm_win_size_map_;

  bool wait_for_cont_frame_;

  bool is_server_;

  std::vector<uint8_t> EncodeHeaders(
      const std::unordered_map<std::string, std::string> &headers_map);

  int HandleStaticContent(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path);

  int HandleStaticContent(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path, std::mutex &mut);

  int HandleRouterRequest(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path, const std::string &data);

  int HandleRouterRequest(
      uint32_t frame_stream, SSL *ssl,
      const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<TcpTransport> &transport_ptr, std::string &method,
      std::string &path, const std::string &data, std::mutex &mut);

  int AnswerRequest(uint32_t frame_stream, SSL *ssl,
                    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
                    const std::shared_ptr<TcpTransport> &transport_ptr);

  int AnswerRequest(uint32_t frame_stream, SSL *ssl,
                    const std::shared_ptr<Http2FrameBuilder> &frame_builder_ptr,
                    const std::shared_ptr<TcpTransport> &transport_ptr,
                    std::mutex &mut);

  int HandleDataFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl) override;

  int HandleHeadersFrame(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl) override;

  int HandlePriorityFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl) override;

  int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                           uint32_t read_offset, uint32_t payload_size,
                           uint8_t frame_flags, SSL *ssl) override;

  int HandleSettingsFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl) override;

  int HandlePingFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl) override;

  int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                        uint32_t read_offset, uint32_t payload_size,
                        uint8_t frame_flags, SSL *ssl) override;

  int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) override;

  int HandleContinuationFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl) override;

  int HandleDataFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleHeadersFrame(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandlePriorityFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                           uint32_t read_offset, uint32_t payload_size,
                           uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleSettingsFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandlePingFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                        uint32_t read_offset, uint32_t payload_size,
                        uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl, std::mutex &mut);

  int HandleContinuationFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl, std::mutex &mut);
};

#endif  // FRAMEBUILDER_HPP
