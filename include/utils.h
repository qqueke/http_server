// Copyright 2024 Joao Brotas
//
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file utils.h
 * @brief Contains utility functions and definitions for handling HTTP2, QUIC,
 * encryption, and command-line parsing.
 *
 * This file provides utility functions and constants for protocols such as
 * HTTP2 and QUIC, along with various utility functions for error handling, hex
 * encoding/decoding, SSL key logging, and command-line argument parsing.
 */

#ifndef INCLUDE_UTILS_H_
#define INCLUDE_UTILS_H_

#include <lsqpack.h>
#include <lsxpack_header.h>
#include <msquic.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <utility>

// Define macros for program constants and flags
#define _CRT_SECURE_NO_WARNINGS \
  1                   /**< Disable certain secure warnings in MSVC. */
#define UDP_PORT 4567 /**< The port used for UDP connections. */

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) \
  (void)(P) /**< Macro to mark unused parameters. */
#endif

#define ROUTE_HANDLER                                \
  std::function<std::pair<std::string, std::string>( \
      const std::string &)> /**< Defines a route handler function type. */

#define OPT_ROUTE_HANDLER                                                   \
  std::function<                                                            \
      std::pair<std::unordered_map<std::string, std::string>, std::string>( \
          const std::string &)> /**< Defines a route handler function type. */

#define STATUS_CODE std::string /**< Type alias for HTTP status codes. */

/**
 * @enum Protocol
 * @brief Enum representing supported HTTP protocols.
 */
enum class Protocol { HTTP1, HTTP2, HTTP3 };

/**
 * @enum CompressionType
 * @brief Enum for supported compression types.
 */
enum CompressionType { DEFLATE, GZIP };

/**
 * @brief Various constants used throughout the program.
 */
enum : int {
  BUFFER_SIZE = 1024,    /**< Default buffer size. */
  ERROR = -1,            /**< Error return code. */
  TIMEOUT_SECONDS = 5,   /**< Timeout duration in seconds. */
  MAX_CONNECTIONS = 100, /**< Maximum number of allowed connections. */
  MAX_PENDING_CONNECTIONS =
      1000000,      /**< Maximum number of pending connections. */
  HTTP_PORT = 4433, /**< Default HTTP port. */
};

/**
 * @brief Constants related to transport configurations and settings.
 */
enum : uint32_t {
  MAX_RETRIES = 5, /**< Maximum number of retries for transport operations. */
  SEND_DELAY_MS = 20, /**< Delay between sending packets in milliseconds. */
  RECV_DELAY_MS = 20, /**< Delay between receiving packets in milliseconds. */
  MAX_PAYLOAD_FRAME_SIZE = 16384, /**< Maximum payload frame size in bytes. */
  FRAME_HEADER_LENGTH = 9,        /**< Frame header length in bytes. */
  MAX_FLOW_WINDOW_SIZE = 2147483646, /**< Maximum flow window size. */
  PREFACE_LENGTH = 24,               /**< Length of the QUIC preface. */
};

/**
 * @enum HTTP2Flags
 * @brief Flags used in HTTP/2 frame types for controlling stream behavior.
 */
enum HTTP2Flags : uint8_t {
  NONE_FLAG = 0x0, /**< No flags set. */

  // DATA frame flags
  END_STREAM_FLAG = 0x1, /**< Bit 0: END_STREAM flag. */
  PADDED_FLAG = 0x8,     /**< Bit 3: PADDED flag. */

  // HEADERS frame flags
  END_HEADERS_FLAG = 0x4, /**< Bit 2: END_HEADERS flag. */
  PRIORITY_FLAG = 0x20,   /**< Bit 4: PRIORITY flag. */

  // SETTINGS frame flags
  SETTINGS_ACK_FLAG = 0x1, /**< Bit 0: SETTINGS_ACK flag. */

  // PING frame flags
  PING_ACK_FLAG = 0x1, /**< Bit 0: PING_ACK flag. */
};

/**
 * @enum HTTP2ErrorCode
 * @brief Error codes used in HTTP/2 communication.
 */
enum HTTP2ErrorCode : uint32_t {
  NO_ERROR = 0x0,            /**< Graceful shutdown. */
  PROTOCOL_ERROR = 0x1,      /**< General protocol error. */
  INTERNAL_ERROR = 0x2,      /**< Internal error. */
  FLOW_CONTROL_ERROR = 0x3,  /**< Flow control error. */
  SETTINGS_TIMEOUT = 0x4,    /**< SETTINGS frame timeout. */
  STREAM_CLOSED = 0x5,       /**< Frame received after stream closed. */
  FRAME_SIZE_ERROR = 0x6,    /**< Invalid frame size. */
  REFUSED_STREAM = 0x7,      /**< Stream refused before processing. */
  CANCEL = 0x8,              /**< Stream no longer needed. */
  COMPRESSION_ERROR = 0x9,   /**< Compression context error. */
  CONNECT_ERROR = 0xa,       /**< CONNECT request failure. */
  ENHANCE_YOUR_CALM = 0xb,   /**< Excessive load error. */
  INADEQUATE_SECURITY = 0xc, /**< Security requirements not met. */
  HTTP_1_1_REQUIRED = 0xd    /**< HTTP/1.1 required instead of HTTP/2. */
};

/**
 * @enum Frame
 * @brief Defines the frame types used in HTTP/2 communication.
 */
enum Frame : uint8_t {
  DATA = 0x0,          /**< Data frame. */
  HEADERS = 0x1,       /**< Headers frame. */
  PRIORITY = 0x2,      /**< Priority frame. */
  RST_STREAM = 0x3,    /**< Reset stream frame. */
  SETTINGS = 0x4,      /**< Settings frame. */
  PUSH_PROMISE = 0x5,  /**< Push promise frame. */
  PING = 0x6,          /**< Ping frame. */
  GOAWAY = 0x7,        /**< Goaway frame. */
  WINDOW_UPDATE = 0x8, /**< Window update frame. */
  CONTINUATION = 0x9   /**< Continuation frame. */
};

/**
 * @enum HTTP2Settings
 * @brief Defines settings for HTTP/2 communication.
 */
enum HTTP2Settings : uint16_t {
  HEADER_TABLE_SIZE = 0x1,      /**< Default: 4096. */
  ENABLE_PUSH = 0x2,            /**< Default: 1. */
  MAX_CONCURRENT_STREAMS = 0x3, /**< Default: Infinite. */
  INITIAL_WINDOW_SIZE = 0x4,    /**< Default: 65535. */
  MAX_FRAME_SIZE = 0x5,         /**< Default: 16384. */
  MAX_HEADER_LIST_SIZE = 0x6    /**< Default: Infinite. */
};

/**
 * @struct HTTP2Context
 * @brief Structure to hold the context of an HTTP/2 stream.
 */
struct HTTP2Context {
  SSL *ssl;                /**< Pointer to the SSL context for this stream. */
  struct lshpack_enc *enc; /**< Pointer to the HPACK encoder context. */
  uint32_t stream_id;      /**< Stream ID for the HTTP/2 connection. */

  uint8_t instance_type; /**< Type of the instance. */
  void *instance_ctx;    /**< Pointer to the instance context. */

  /**
   * @brief Constructor for HTTP2Context.
   *
   * Initializes the HTTP2Context with SSL, HPACK encoder, stream ID, instance
   * type, and instance context.
   *
   * @param s Pointer to the SSL context.
   * @param e Pointer to the HPACK encoder.
   * @param id The stream ID.
   * @param type The instance type.
   * @param instance Pointer to the instance context.
   */
  HTTP2Context(SSL *s, struct lshpack_enc *e, uint32_t id, uint8_t type,
               void *instance)
      : ssl(s),
        enc(e),
        stream_id(id),
        instance_type(type),
        instance_ctx(instance) {}
};

// External variables
extern const QUIC_BUFFER Alpn;      /**< ALPN protocol buffer for QUIC. */
extern const char *SslKeyLogEnvVar; /**< SSL key log environment variable. */

/**
 * @struct st_hblock_ctx
 * @brief Structure for handling HTTP/2 header block context.
 */
typedef struct st_hblock_ctx {
  struct lsxpack_header xhdr; /**< HPACK header information. */
  size_t buf_off;             /**< Offset in the buffer. */
  char buf[0x1000];           /**< Buffer for decoded headers. */
  std::unordered_map<std::string, std::string>
      *decoded_headers_map; /**< Map of decoded headers. */
} hblock_ctx_t;

/**
 * @struct QUIC_CREDENTIAL_CONFIG_HELPER
 * @brief Helper structure for managing QUIC credential configurations.
 */
typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
  QUIC_CREDENTIAL_CONFIG CredConfig; /**< QUIC credential configuration. */
  union {
    QUIC_CERTIFICATE_HASH CertHash;            /**< Certificate hash. */
    QUIC_CERTIFICATE_HASH_STORE CertHashStore; /**< Certificate hash store. */
    QUIC_CERTIFICATE_FILE CertFile;            /**< Certificate file. */
    QUIC_CERTIFICATE_FILE_PROTECTED
    CertFileProtected; /**< Protected certificate file. */
  };
} QUIC_CREDENTIAL_CONFIG_HELPER;

/**
 * @brief Checks if a specific HTTP2 flag is set.
 *
 * @param flags The HTTP2 flags.
 * @param flag The specific flag to check.
 * @return Returns true if the flag is set, otherwise false.
 */
bool isFlagSet(uint8_t flags, HTTP2Flags flag);

/**
 * @brief Retrieves the SSL error message for the given error code.
 *
 * @param error The SSL error code.
 * @return A string containing the error message.
 */
std::string GetSSLErrorMessage(int error);

/**
 * @brief Prints the usage information for the program.
 */
void PrintUsage();

/**
 * @brief Looks up a flag in the command-line arguments.
 *
 * @param argc The argument count.
 * @param argv The argument vector.
 * @param name The name of the flag to search for.
 * @return TRUE if the flag is found, otherwise FALSE.
 */
BOOLEAN
GetFlag(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[],
        _In_z_ const char *name);

/**
 * @brief Retrieves the value of a command-line argument.
 *
 * @param argc The argument count.
 * @param argv The argument vector.
 * @param name The name of the argument to retrieve.
 * @return The value of the argument, or nullptr if not found.
 */
_Ret_maybenull_ _Null_terminated_ const char *GetValue(
    _In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[],
    _In_z_ const char *name);

/**
 * @brief Retrieves the value of a command-line argument as a string.
 *
 * @param argc The argument count.
 * @param argv The argument vector.
 * @param name The name of the argument to retrieve.
 * @return The value of the argument.
 */
std::string GetValue2(int argc, char *argv[], const std::string &name);

/**
 * @brief Decodes a hex character into its decimal value.
 *
 * @param c The hex character to decode.
 * @return The decimal value of the hex character.
 */
uint8_t DecodeHexChar(_In_ char c);

/**
 * @brief Decodes a hex buffer into a byte buffer.
 *
 * @param HexBuffer The hex string to decode.
 * @param OutBufferLen The length of the output buffer.
 * @param OutBuffer The output byte buffer.
 * @return The number of bytes decoded.
 */
uint32_t DecodeHexBuffer(_In_z_ const char *HexBuffer,
                         _In_ uint32_t OutBufferLen,
                         _Out_writes_to_(OutBufferLen, return)
                             uint8_t *OutBuffer);

/**
 * @brief Encodes a byte buffer into a hex string.
 *
 * @param Buffer The byte buffer to encode.
 * @param BufferLen The length of the byte buffer.
 * @param HexString The output hex string.
 */
void EncodeHexBuffer(_In_reads_(BufferLen) uint8_t *Buffer,
                     _In_ uint8_t BufferLen,
                     _Out_writes_bytes_(2 * BufferLen) char *HexString);

/**
 * @brief Writes SSL key log information to a file.
 *
 * @param FileName The name of the log file.
 * @param TlsSecrets The TLS secrets to log.
 */
void WriteSslKeyLogFile(_In_z_ const char *FileName,
                        _In_ QUIC_TLS_SECRETS *TlsSecrets);

#endif  // INCLUDE_UTILS_H_
