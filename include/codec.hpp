/**
 * @file Codec.hpp
 * @brief Interface and implementations for HTTP header encoding/decoding
 */
#ifndef CODEC_HPP
#define CODEC_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

class ICodec {
 public:
  virtual ~ICodec() = default;

  virtual void Encode(
      void *context,
      const std::unordered_map<std::string, std::string> &headersMap,
      std::vector<uint8_t> &encodedHeaders) = 0;

  virtual void Decode(
      void *context, std::vector<uint8_t> &encodedHeaders,
      std::unordered_map<std::string, std::string> &decodedHeadersMap) = 0;
};

/**
 * @class HPACKCodec
 * @brief Implementation of HPACK encoding and decoding
 */
class HpackCodec : public ICodec {
 public:
  HpackCodec() = default;
  ~HpackCodec() override = default;

  /**
   * @brief Encode headers using HPACK algorithm
   * @param encoder HPACK encoder instance
   * @param headers Headers to encode
   * @param encodedHeaders Output buffer for encoded headers
   */
  void Encode(void *context,
              const std::unordered_map<std::string, std::string> &headersMap,
              std::vector<uint8_t> &encodedHeaders) override;

  /**
   * @brief Decode headers using HPACK algorithm
   * @param decoder HPACK decoder instance
   * @param encodedHeaders Encoded headers buffer
   * @param decodedHeaders Output map for decoded headers
   */
  void Decode(
      void *context, std::vector<uint8_t> &encodedHeaders,
      std::unordered_map<std::string, std::string> &decodedHeadersMap) override;
};

/**
 * @class QPACKCodec
 * @brief Implementation of QPACK encoding and decoding
 */
class QpackCodec : public ICodec {
 public:
  QpackCodec() = default;
  ~QpackCodec() override = default;

  /**
   * @brief Encode headers using QPACK algorithm
   * @param stream QUIC stream
   * @param headers Headers to encode
   * @param encodedHeaders Output buffer for encoded headers
   */
  void Encode(void *context,
              const std::unordered_map<std::string, std::string> &headers,
              std::vector<uint8_t> &encodedHeaders) override;

  /**
   * @brief Decode headers using QPACK algorithm
   * @param stream QUIC stream
   * @param encodedHeaders Encoded headers buffer
   */
  void Decode(
      void *context, std::vector<uint8_t> &encodedHeaders,
      std::unordered_map<std::string, std::string> &decodedHeaders) override;
};

#endif  // CODEC_HPP
