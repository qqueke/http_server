// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file codec.h
 * @brief Interface and implementations for HTTP header encoding/decoding.
 *
 * This file provides the `ICodec` interface and its implementations:
 * `HpackCodec` and `QpackCodec`. These classes are responsible for encoding and
 * decoding HTTP headers using the HPACK and QPACK algorithms, respectively.
 */
#ifndef INCLUDE_CODEC_H_
#define INCLUDE_CODEC_H_

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "msquic.h"

/**
 * @interface ICodec
 * @brief Interface for HTTP header encoding/decoding.
 *
 * This interface defines the methods required for encoding and decoding HTTP
 * headers. It can be implemented for different encoding/decoding algorithms
 * such as HPACK and QPACK.
 */
class ICodec {
 public:
  virtual ~ICodec() = default;

  /**
   * @brief Encodes HTTP headers into a byte stream.
   * @param context The context for encoding.
   * @param headers_map A map of HTTP headers to encode.
   * @param encoded_headers A vector that will hold the encoded headers.
   */
  virtual void Encode(
      void *context,
      const std::unordered_map<std::string, std::string> &headers_map,
      std::vector<uint8_t> &encoded_headers) = 0;

  /**
   * @brief Decodes a byte stream into HTTP headers.
   * @param context The context for decoding.
   * @param encoded_headers A vector containing the encoded headers.
   * @param decoded_headers_map A map to store the decoded HTTP headers.
   */
  virtual void Decode(
      void *context, std::vector<uint8_t> &encoded_headers,
      std::unordered_map<std::string, std::string> &decoded_headers_map) = 0;
};

/**
 * @class HpackCodec
 * @brief Implementation of HPACK encoding and decoding.
 *
 * The `HpackCodec` class implements the HPACK algorithm for HTTP/2 header
 * compression. It provides methods to encode and decode HTTP headers.
 */
class HpackCodec : public ICodec {
 public:
  HpackCodec() = default;
  ~HpackCodec() override = default;

  /**
   * @brief Encodes headers using the HPACK algorithm.
   *
   * This method encodes the given HTTP headers into a compressed byte stream.
   *
   * @param context A pointer to a struct lshpack_enc encoder.
   * @param headers_map A map of HTTP headers to encode.
   * @param encoded_headers A vector to store the encoded headers.
   */
  void Encode(void *context,
              const std::unordered_map<std::string, std::string> &headers_map,
              std::vector<uint8_t> &encoded_headers) override;

  /**
   * @brief Decodes headers using the HPACK algorithm.
   *
   * This method decodes the compressed byte stream into HTTP headers.
   *
   * @param context A pointer to a struct lshpack_dec decoder.
   * @param encoded_headers A vector containing the encoded headers.
   * @param decoded_headers_map A map to store the decoded HTTP headers.
   */
  void Decode(void *context, std::vector<uint8_t> &encoded_headers,
              std::unordered_map<std::string, std::string> &decoded_headers_map)
      override;
};

/**
 * @class QpackCodec
 * @brief Implementation of QPACK encoding and decoding.
 *
 * The `QpackCodec` class implements the QPACK algorithm for HTTP/3 header
 * compression. It provides methods to encode and decode HTTP headers.
 */
class QpackCodec : public ICodec {
 public:
  QpackCodec() = default;

  /**
   * @brief Constructs a QpackCodec instance with a given QUIC API table.
   * @param ms_quic The QUIC API table used for QUIC stream operations.
   */
  explicit QpackCodec(const QUIC_API_TABLE *ms_quic) : ms_quic_(ms_quic) {}

  ~QpackCodec() override = default;

  /**
   * @brief Encodes headers using the QPACK algorithm.
   *
   * This method encodes the given HTTP headers into a compressed byte stream
   * using QPACK.
   *
   * @param context A pointer to a QUIC stream handle.
   * @param headers A map of HTTP headers to encode.
   * @param encoded_headers A vector to store the encoded headers.
   */
  void Encode(void *context,
              const std::unordered_map<std::string, std::string> &headers,
              std::vector<uint8_t> &encoded_headers) override;

  /**
   * @brief Decodes headers using the QPACK algorithm.
   *
   * This method decodes the compressed byte stream into HTTP headers using
   * QPACK.
   *
   * @param context A pointer to a QUIC stream handle.
   * @param encoded_headers A vector containing the encoded headers.
   * @param decoded_headers A map to store the decoded HTTP headers.
   */
  void Decode(
      void *context, std::vector<uint8_t> &encoded_headers,
      std::unordered_map<std::string, std::string> &decoded_headers) override;

 private:
  /** Pointer to the QUIC API table used for QUIC stream operations. */
  const QUIC_API_TABLE *ms_quic_;
};

#endif  // INCLUDE_CODEC_H_
