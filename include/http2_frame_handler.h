#ifndef FRAMEBUILDER_HPP
#define FRAMEBUILDER_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "common.h"
#include "crypto.h"
#include "router.h"

struct Http2FrameContext {
  const std::vector<uint8_t> &read_buffer;

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &decoded_headers_map;

  std::unordered_map<uint32_t, std::vector<uint8_t>> &encoded_headers_map;

  std::unordered_map<uint32_t, std::string> &data_map;

  struct lshpack_enc &enc;

  struct lshpack_dec &dec;

  uint32_t &conn_win_size;

  std::unordered_map<uint32_t, uint32_t> &strm_win_size_map;

  bool &expect_cont_frame;

  // Constructor that accepts references to the original data
  Http2FrameContext(
      const std::vector<uint8_t> &read_buf,
      std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
          &decodedHeadersMap,
      std::unordered_map<uint32_t, std::vector<uint8_t>> &encoded_headers_map,
      std::unordered_map<uint32_t, std::string> &dataMap,
      struct lshpack_enc &enc, struct lshpack_dec &dec, uint32_t &conn_win_size,
      std::unordered_map<uint32_t, uint32_t> &strm_win_size_map,
      bool &expectingContFrame)
      : read_buffer(read_buf),
        decoded_headers_map(decodedHeadersMap),
        encoded_headers_map(encoded_headers_map),
        data_map(dataMap),
        enc(enc),
        dec(dec),
        conn_win_size(conn_win_size),
        strm_win_size_map(strm_win_size_map),
        expect_cont_frame(expectingContFrame) {}
};

class IHttp2FrameHandler {
 public:
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

class Http2ServerFrameHandler : IHttp2FrameHandler {
 public:
  explicit Http2ServerFrameHandler(
      const std::shared_ptr<TcpTransport> &tcpTransport,
      const std::shared_ptr<Http2FrameBuilder> &http2FrameBuilder,
      const std::shared_ptr<HpackCodec> &hpackCodec,
      const std::shared_ptr<Router> &router)
      : transport_(tcpTransport),
        frame_builder_(http2FrameBuilder),
        codec_(hpackCodec),
        router_(router) {}

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

class Http2ClientFrameHandler : IHttp2FrameHandler {
 public:
  explicit Http2ClientFrameHandler(
      const std::shared_ptr<TcpTransport> &tcpTransport,
      const std::shared_ptr<Http2FrameBuilder> &http2FrameBuilder,
      const std::shared_ptr<HpackCodec> &hpackCodec)
      : transport_(tcpTransport),
        frame_builder_(http2FrameBuilder),
        codec_(hpackCodec) {}

  int ProcessFrame(void *context, uint8_t frame_type, uint32_t frame_stream,
                   uint32_t read_offset, uint32_t payload_size,
                   uint8_t frame_flags, SSL *ssl) override;

  int ProcessFrame_TS(void *context, uint8_t frame_type, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl, std::mutex &mut) override;

 private:
  std::weak_ptr<TcpTransport> transport_;

  std::weak_ptr<Http2FrameBuilder> frame_builder_;

  std::weak_ptr<HpackCodec> codec_;

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

#endif  // FRAMEBUILDER_HPP
