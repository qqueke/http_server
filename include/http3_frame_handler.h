#ifndef HTTP3_FRAME_BUILDER_HPP
#define HTTP3_FRAME_BUILDER_HPP

#include <memory>

#include "codec.h"
#include "http3_frame_builder.h"
#include "router.h"
#include "transport.h"

class Http3FrameHandler {
public:
  // Server constructor
  explicit Http3FrameHandler(
      const std::shared_ptr<QuicTransport> &quic_transport,
      const std::shared_ptr<Http3FrameBuilder> &http3_frame_builder,
      const std::shared_ptr<QpackCodec> &qpack_codec,
      const std::shared_ptr<Router> &router);

  // Client constructor
  explicit Http3FrameHandler(
      const std::shared_ptr<QuicTransport> &quic_transport,
      const std::shared_ptr<Http3FrameBuilder> &http3_frame_builder,
      const std::shared_ptr<QpackCodec> &qpack_codec);

  ~Http3FrameHandler();

  int ProcessFrames(HQUIC &stream, std::vector<uint8_t> &stream_buffer);

  int ProcessFrame(HQUIC &stream, std::vector<uint8_t>::iterator &iter,
                   uint64_t frame_type, uint64_t payload_size,
                   std::unordered_map<std::string, std::string> &headers_map,
                   std::string &data);

  // int ProcessFrame_TS(void *context, uint8_t frame_type, uint32_t
  // frame_stream,
  //                     uint32_t read_offset, uint32_t payload_size,
  //                     uint8_t frame_flags, SSL *ssl, std::mutex &mut);

private:
  std::weak_ptr<Router> router_;

  std::weak_ptr<QuicTransport> transport_;

  std::weak_ptr<Http3FrameBuilder> frame_builder_;

  std::weak_ptr<QpackCodec> codec_;

  // std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
  //     quic_decoded_headers_map_;
  //
  // std::unordered_map<uint32_t, std::vector<uint8_t>>
  // encoded_headers_buf_map_;
  //
  // std::unordered_map<uint32_t, std::string> quic_data_map_;

  bool is_server_;

  int HandleDataFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl);

  int HandleHeadersFrame(void *context, uint32_t frame_stream,
                         uint32_t read_offset, uint32_t payload_size,
                         uint8_t frame_flags, SSL *ssl);

  int HandlePriorityFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl);

  int HandleRstStreamFrame(void *context, uint32_t frame_stream,
                           uint32_t read_offset, uint32_t payload_size,
                           uint8_t frame_flags, SSL *ssl);

  int HandleSettingsFrame(void *context, uint32_t frame_stream,
                          uint32_t read_offset, uint32_t payload_size,
                          uint8_t frame_flags, SSL *ssl);

  int HandlePingFrame(void *context, uint32_t frame_stream,
                      uint32_t read_offset, uint32_t payload_size,
                      uint8_t frame_flags, SSL *ssl);

  int HandleGoAwayFrame(void *context, uint32_t frame_stream,
                        uint32_t read_offset, uint32_t payload_size,
                        uint8_t frame_flags, SSL *ssl);

  int HandleWindowUpdateFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl);

  int HandleContinuationFrame(void *context, uint32_t frame_stream,
                              uint32_t read_offset, uint32_t payload_size,
                              uint8_t frame_flags, SSL *ssl);

  // int HandleDataFrame_TS(void *context, uint32_t frame_stream,
  //                        uint32_t read_offset, uint32_t payload_size,
  //                        uint8_t frame_flags, SSL *ssl, std::mutex &mut);
  //
  // int HandleHeadersFrame_TS(void *context, uint32_t frame_stream,
  //                           uint32_t read_offset, uint32_t payload_size,
  //                           uint8_t frame_flags, SSL *ssl, std::mutex &mut);
  //
  // int HandlePriorityFrame_TS(void *context, uint32_t frame_stream,
  //                            uint32_t read_offset, uint32_t payload_size,
  //                            uint8_t frame_flags, SSL *ssl, std::mutex &mut);
  //
  // int HandleRstStreamFrame_TS(void *context, uint32_t frame_stream,
  //                             uint32_t read_offset, uint32_t payload_size,
  //                             uint8_t frame_flags, SSL *ssl, std::mutex
  //                             &mut);
  //
  // int HandleSettingsFrame_TS(void *context, uint32_t frame_stream,
  //                            uint32_t read_offset, uint32_t payload_size,
  //                            uint8_t frame_flags, SSL *ssl, std::mutex &mut);
  //
  // int HandlePingFrame_TS(void *context, uint32_t frame_stream,
  //                        uint32_t read_offset, uint32_t payload_size,
  //                        uint8_t frame_flags, SSL *ssl, std::mutex &mut);
  //
  // int HandleGoAwayFrame_TS(void *context, uint32_t frame_stream,
  //                          uint32_t read_offset, uint32_t payload_size,
  //                          uint8_t frame_flags, SSL *ssl, std::mutex &mut);
  //
  // int HandleWindowUpdateFrame_TS(void *context, uint32_t frame_stream,
  //                                uint32_t read_offset, uint32_t payload_size,
  //                                uint8_t frame_flags, SSL *ssl,
  //                                std::mutex &mut);
  //
  // int HandleContinuationFrame_TS(void *context, uint32_t frame_stream,
  //                                uint32_t read_offset, uint32_t payload_size,
  //                                uint8_t frame_flags, SSL *ssl,
  //                                std::mutex &mut);
};

#endif
