/**
 * @file FrameBuilder.hpp
 * @brief HTTP frame building utilities
 */
#ifndef FRAME_BUILDER_HPP
#define FRAME_BUILDER_HPP

#include <cstdint>
#include <string>
#include <vector>

class Http2FrameBuilder {
public:
  std::vector<uint8_t> BuildDataFrame(const std::string &data,
                                      uint32_t streamId = 0);

  std::vector<uint8_t>
  BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders,
                   uint32_t streamId);

  std::vector<uint8_t> BuildGoAwayFrame(uint32_t streamId, uint32_t errorCode);

  std::vector<uint8_t> BuildSettingsFrame(uint8_t frameFlags);

  std::vector<uint8_t> BuildRstStreamFrame(uint32_t streamId,
                                           uint32_t errorCode);

  std::vector<uint8_t> BuildWindowUpdateFrame(uint32_t streamId,
                                              uint32_t increment);
};

class Http3FrameBuilder {
public:
  std::vector<uint8_t> BuildDataFrame(const std::string &data);

  std::vector<uint8_t>
  BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders);

  std::vector<uint8_t> BuildGoAwayFrame(uint32_t streamId);

  std::vector<uint8_t> BuildSettingsFrame();
};

#endif // FRAME_BUILDER_HPP
