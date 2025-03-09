#ifndef HTTP3_FRAME_HANDLER
#define HTTP3_FRAME_HANDLER

#include <memory>

#include "codec.h"
#include "http3_frame_builder.h"
#include "router.h"
#include "static_content_handler.h"
#include "transport.h"

class Http3FrameHandler {
public:
  explicit Http3FrameHandler(
      const std::shared_ptr<QuicTransport> &transport,
      const std::shared_ptr<Http3FrameBuilder> &http3_frame_builder,
      const std::shared_ptr<QpackCodec> &codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr);

  ~Http3FrameHandler();

  int ProcessFrames(HQUIC &stream, std::vector<uint8_t> &stream_buffer);

  int ProcessFrame(HQUIC &stream, std::vector<uint8_t>::iterator &iter,
                   uint64_t frame_type, uint64_t payload_size,
                   std::unordered_map<std::string, std::string> &headers_map,
                   std::string &data);

private:
  void InitializeSharedResources(
      const std::shared_ptr<QuicTransport> &transport,
      const std::shared_ptr<Http3FrameBuilder> &frame_builder,
      const std::shared_ptr<QpackCodec> &hpack_codec,
      const std::shared_ptr<Router> &router = nullptr,
      const std::shared_ptr<StaticContentHandler> &content_handler = nullptr);

  static bool static_init_;

  static std::weak_ptr<Router> router_;

  static std::weak_ptr<QuicTransport> transport_;

  static std::weak_ptr<Http3FrameBuilder> frame_builder_;

  static std::weak_ptr<QpackCodec> codec_;

  static std::weak_ptr<StaticContentHandler> static_content_handler_;

  // std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
  //     quic_decoded_headers_map_;
  //
  // std::unordered_map<uint32_t, std::vector<uint8_t>>
  // encoded_headers_buf_map_;
  //
  // std::unordered_map<uint32_t, std::string> quic_data_map_;

  bool is_server_;

  std::vector<uint8_t> EncodeHeaders(
      const std::unordered_map<std::string, std::string> &headers_map);

  int HandleStaticContent(
      HQUIC &stream, std::unordered_map<std::string, std::string> &headers_map,
      std::string &data,
      const std::shared_ptr<Http3FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<QuicTransport> &transport_ptr);

  int HandleRouterRequest(
      HQUIC &stream,
      const std::shared_ptr<Http3FrameBuilder> &frame_builder_ptr,
      const std::shared_ptr<QuicTransport> &transport_ptr, std::string &method,
      std::string &path, const std::string &data);

  int AnswerRequest(HQUIC &stream,
                    std::unordered_map<std::string, std::string> &headers_map,
                    std::string &data);

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
