/**framebui
 * @file http2_frame_builder.h
 * @brief HTTP frame building utilities
 */
#ifndef HTTP2_FRAME_BUILDER
#define HTTP2_FRAME_BUILDER

#include <cstdint>
#include <string>
#include <vector>

#include "utils.h"

class Http2FrameBuilder {
public:
  std::vector<uint8_t>
  BuildFrame(Frame type, uint8_t frame_flags = 0, uint32_t stream_id = 0,
             uint32_t error_code = 0, uint32_t increment = 0,
             const std::vector<uint8_t> &encoded_headers = {},
             const std::string &data = "");

  std::vector<uint8_t> BuildDataFrame(const std::string &data,
                                      uint32_t stream_id = 0);

  std::vector<uint8_t>
  BuildHeaderFrame(const std::vector<uint8_t> &encoded_headers,
                   uint32_t stream_id);

  std::vector<uint8_t> BuildGoAwayFrame(uint32_t stream_id,
                                        uint32_t error_code);

  std::vector<uint8_t> BuildSettingsFrame(uint8_t frame_flags);

  std::vector<uint8_t> BuildRstStreamFrame(uint32_t stream_id,
                                           uint32_t error_code);

  std::vector<uint8_t> BuildWindowUpdateFrame(uint32_t stream_id,
                                              uint32_t increment);
};

#endif
