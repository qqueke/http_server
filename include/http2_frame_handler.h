#ifndef HTTP2_FRAME_BUILDER_HPP
#define HTTP2_FRAME_BUILDER_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "common.h"
#include "crypto.h"
#include "router.h"

class IHttp2FrameHandler {
public:
  virtual ~IHttp2FrameHandler() = default;
  // virtual ~IHttp2FrameHandler() = default;
  virtual int ProcessFrame(void *context, uint8_t frame_type,
                           uint32_t frame_stream, uint32_t read_offset,
                           uint32_t payload_size, uint8_t frame_flags,
                           SSL *ssl) = 0;

  virtual int ProcessFrame_TS(void *context, uint8_t frame_type,
                              uint32_t frame_stream, uint32_t read_offset,
                              uint32_t payload_size, uint8_t frame_flags,
                              SSL *ssl, std::mutex &mut) = 0;

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

  virtual int HandleDataFrame_TS(void *context, uint32_t frame_stream,
                                 uint32_t read_offset, uint32_t payload_size,
                                 uint8_t frame_flags, SSL *ssl,
                                 std::mutex &mut) = 0;

  virtual int HandleHeadersFrame_TS(void *context, uint32_t frame_stream,
                                    uint32_t read_offset, uint32_t payload_size,
                                    uint8_t frame_flags, SSL *ssl,
                                    std::mutex &mut) = 0;

  virtual int HandlePriorityFrame_TS(void *context, uint32_t frame_stream,
                                     uint32_t read_offset,
                                     uint32_t payload_size, uint8_t frame_flags,
                                     SSL *ssl, std::mutex &mut) = 0;

  virtual int HandleRstStreamFrame_TS(void *context, uint32_t frame_stream,
                                      uint32_t read_offset,
                                      uint32_t payload_size,
                                      uint8_t frame_flags, SSL *ssl,
                                      std::mutex &mut) = 0;

  virtual int HandleSettingsFrame_TS(void *context, uint32_t frame_stream,
                                     uint32_t read_offset,
                                     uint32_t payload_size, uint8_t frame_flags,
                                     SSL *ssl, std::mutex &mut) = 0;

  virtual int HandlePingFrame_TS(void *context, uint32_t frame_stream,
                                 uint32_t read_offset, uint32_t payload_size,
                                 uint8_t frame_flags, SSL *ssl,
                                 std::mutex &mut) = 0;

  virtual int HandleGoAwayFrame_TS(void *context, uint32_t frame_stream,
                                   uint32_t read_offset, uint32_t payload_size,
                                   uint8_t frame_flags, SSL *ssl,
                                   std::mutex &mut) = 0;

  virtual int HandleWindowUpdateFrame_TS(void *context, uint32_t frame_stream,
                                         uint32_t read_offset,
                                         uint32_t payload_size,
                                         uint8_t frame_flags, SSL *ssl,
                                         std::mutex &mut) = 0;

  virtual int HandleContinuationFrame_TS(void *context, uint32_t frame_stream,
                                         uint32_t read_offset,
                                         uint32_t payload_size,
                                         uint8_t frame_flags, SSL *ssl,
                                         std::mutex &mut) = 0;
};

class Http2FrameHandler : IHttp2FrameHandler {
public:
  // Server constructor
  explicit Http2FrameHandler(
      const std::shared_ptr<TcpTransport> &tcp_transport,
      const std::shared_ptr<Http2FrameBuilder> &http2_frame_builder,
      const std::shared_ptr<HpackCodec> &hpack_codec,
      const std::shared_ptr<Router> &router,
      const std::vector<uint8_t> &read_buf);

  // Client constructor
  explicit Http2FrameHandler(
      const std::shared_ptr<TcpTransport> &tcp_transport,
      const std::shared_ptr<Http2FrameBuilder> &http2_frame_builder,
      const std::shared_ptr<HpackCodec> &hpack_codec,
      const std::vector<uint8_t> &read_buf);

  ~Http2FrameHandler();

  int ProcessFrame(void *context, uint8_t frame_type, uint32_t frame_stream,
                   uint32_t read_offset, uint32_t payload_size,
                   uint8_t frame_flags, SSL *ssl) override;

  int ProcessFrame_TS(void *context, uint8_t frame_type, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut) override;

private:
  std::weak_ptr<Router> router_;

  std::weak_ptr<TcpTransport> transport_;

  std::weak_ptr<Http2FrameBuilder> frame_builder_;

  std::weak_ptr<HpackCodec> codec_;

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

  int HandleDataFrame_TS(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl,
                         std::mutex &mut) override;

  int HandleHeadersFrame_TS(void *context, uint32_t frame_stream,
                            uint32_t read_offset, uint32_t payload_size,
                            uint8_t frame_flags, SSL *ssl,
                            std::mutex &mut) override;

  int HandlePriorityFrame_TS(void *context, uint32_t frame_stream,
                             uint32_t read_offset, uint32_t payload_size,
                             uint8_t frame_flags, SSL *ssl,
                             std::mutex &mut) override;

  int HandleRstStreamFrame_TS(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl,
                              std::mutex &mut) override;

  int HandleSettingsFrame_TS(void *context, uint32_t frame_stream,
                             uint32_t read_offset, uint32_t payload_size,
                             uint8_t frame_flags, SSL *ssl,
                             std::mutex &mut) override;

  int HandlePingFrame_TS(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl,
                         std::mutex &mut) override;

  int HandleGoAwayFrame_TS(void *context, uint32_t frame_stream,
                           uint32_t read_offset, uint32_t payload_size,
                           uint8_t frame_flags, SSL *ssl,
                           std::mutex &mut) override;

  int HandleWindowUpdateFrame_TS(void *context, uint32_t frame_stream,
                                 uint32_t read_offset, uint32_t payload_size,
                                 uint8_t frame_flags, SSL *ssl,
                                 std::mutex &mut) override;

  int HandleContinuationFrame_TS(void *context, uint32_t frame_stream,
                                 uint32_t read_offset, uint32_t payload_size,
                                 uint8_t frame_flags, SSL *ssl,
                                 std::mutex &mut) override;
};

#endif // FRAMEBUILDER_HPP
