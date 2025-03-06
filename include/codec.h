/**
 * @file Codec.h
 * @brief Interface and implementations for HTTP header encoding/decoding
 */
#ifndef CODEC_HPP
#define CODEC_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "msquic.h"

class ICodec {
public:
  virtual ~ICodec() = default;

  virtual void
  Encode(void *context,
         const std::unordered_map<std::string, std::string> &headers_map,
         std::vector<uint8_t> &encoded_headers) = 0;

  virtual void
  Decode(void *context, std::vector<uint8_t> &encoded_headers,
         std::unordered_map<std::string, std::string> &decoded_headers_map) = 0;
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
   * @param encoded_headers Output buffer for encoded headers
   */
  void Encode(void *context,
              const std::unordered_map<std::string, std::string> &headers_map,
              std::vector<uint8_t> &encoded_headers) override;

  /**
   * @brief Decode headers using HPACK algorithm
   * @param decoder HPACK decoder instance
   * @param encoded_headers Encoded headers buffer
   * @param decodedHeaders Output map for decoded headers
   */
  void Decode(void *context, std::vector<uint8_t> &encoded_headers,
              std::unordered_map<std::string, std::string> &decoded_headers_map)
      override;
};

/**
 * @class QPACKCodec
 * @brief Implementation of QPACK encoding and decoding
 */
class QpackCodec : public ICodec {
public:
  QpackCodec() = default;

  explicit QpackCodec(const QUIC_API_TABLE *ms_quic) : ms_quic_(ms_quic) {}
  ~QpackCodec() override = default;

  /**
   * @brief Encode headers using QPACK algorithm
   * @param stream QUIC stream
   * @param headers Headers to encode
   * @param encoded_headers Output buffer for encoded headers
   */
  void Encode(void *context,
              const std::unordered_map<std::string, std::string> &headers,
              std::vector<uint8_t> &encoded_headers) override;

  /**
   * @brief Decode headers using QPACK algorithm
   * @param stream QUIC stream
   * @param encoded_headers Encoded headers buffer
   */
  void
  Decode(void *context, std::vector<uint8_t> &encoded_headers,
         std::unordered_map<std::string, std::string> &decodedHeaders) override;

private:
  const QUIC_API_TABLE *ms_quic_;
};

#endif // CODEC_HPP
