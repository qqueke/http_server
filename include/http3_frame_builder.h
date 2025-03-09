/**framebui
 * @file http2_frame_builder.h
 * @brief HTTP frame building utilities
 */
#ifndef HTTP3_FRAME_BUILDER
#define HTTP3_FRAME_BUILDER

#include <vector>

#include "utils.h"

class Http3FrameBuilder {
public:
  std::vector<uint8_t>
  BuildFrame(Frame type, uint32_t stream_id = 0,
             const std::vector<uint8_t> &encoded_headers = {},
             const std::string &data = "");

  std::vector<uint8_t> BuildDataFrame(const std::string &data);

  std::vector<uint8_t> BuildDataFrame(std::vector<uint8_t> bytes,
                                      uint32_t payload_size);

  std::vector<std::vector<uint8_t>> BuildDataFramesFromFile(int fd,
                                                            uint64_t file_size);
  std::vector<uint8_t>
  BuildHeaderFrame(const std::vector<uint8_t> &encoded_headers);

  std::vector<uint8_t> BuildGoAwayFrame(uint32_t stream_id);

  std::vector<uint8_t> BuildSettingsFrame();
};

#endif
