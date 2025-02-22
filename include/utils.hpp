#ifndef UTILS_HPP
#define UTILS_HPP

#include <lsqpack.h>
#include <lsxpack_header.h>
#include <msquic.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto.h"

#define _CRT_SECURE_NO_WARNINGS 1
#define UDP_PORT 4567
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#define ROUTE_HANDLER                                                          \
  std::function<std::string(const std::string &, Protocol, void *,             \
                            const std::string)>
#define STATUS_CODE std::string

enum class Protocol { HTTP1, HTTP2, HTTP3 };

enum : int {
  BUFFER_SIZE = 1024,
  ERROR = -1,
  TIMEOUT_SECONDS = 5,
  MAX_CONNECTIONS = 100,
  MAX_PENDING_CONNECTIONS = 1000,
  HTTP_PORT = 4433,
};

enum HTTP2Flags : uint8_t {
  NONE_FLAG = 0x0, // No flags set

  // DATA frame flags
  END_STREAM_FLAG = 0x1, // Bit 0: END_STREAM flag (0x1)
  PADDED_FLAG = 0x8,     // Bit 3: PADDED flag (0x8)

  // HEADERS frame flags
  END_HEADERS_FLAG = 0x4, // Bit 2: END_HEADERS flag (0x4)
  PRIORITY_FLAG = 0x20,   // Bit 4: PRIORITY flag (0x10)

  // SETTINGS frame flags
  SETTINGS_ACK_FLAG = 0x1, // Bit 0: SETTINGS_ACK flag (0x1)

  // PING frame flags
  PING_ACK_FLAG = 0x1, // Bit 0: PING_ACK flag (0x1)
};

enum HTTP2ErrorCode : uint32_t {
  NO_ERROR = 0x0,            // Graceful shutdown
  PROTOCOL_ERROR = 0x1,      // Unspecific protocol error
  INTERNAL_ERROR = 0x2,      // Unexpected internal error
  FLOW_CONTROL_ERROR = 0x3,  // Flow-control protocol violation
  SETTINGS_TIMEOUT = 0x4,    // No response to SETTINGS frame
  STREAM_CLOSED = 0x5,       // Received frame after stream was closed
  FRAME_SIZE_ERROR = 0x6,    // Frame has invalid size
  REFUSED_STREAM = 0x7,      // Stream refused before processing
  CANCEL = 0x8,              // Stream no longer needed
  COMPRESSION_ERROR = 0x9,   // Compression context issue
  CONNECT_ERROR = 0xa,       // CONNECT request failed
  ENHANCE_YOUR_CALM = 0xb,   // Peer is generating excessive load
  INADEQUATE_SECURITY = 0xc, // Transport security requirements not met
  HTTP_1_1_REQUIRED = 0xd    // HTTP/1.1 required instead of HTTP/2
};

enum Frame : uint8_t {
  DATA = 0x0,
  HEADERS = 0x1,
  PRIORITY = 0x2,
  RST_STREAM = 0x3,
  SETTINGS = 0x4,
  PUSH_PROMISE = 0x5,
  PING = 0x6,
  GOAWAY = 0x7,
  WINDOW_UPDATE = 0x8,
  CONTINUATION = 0x9
};

enum class HTTP2Settings : uint8_t {
  HEADER_TABLE_SIZE = 0x1,      // Default: 4096
  ENABLE_PUSH = 0x2,            // Default: 1
  MAX_CONCURRENT_STREAMS = 0x3, // Default: Infinite
  INITIAL_WINDOW_SIZE = 0x4,    // Default: 65535
  MAX_FRAME_SIZE = 0x5,         // Default: 16384
  MAX_HEADER_LIST_SIZE = 0x6    // Default: Infinite
};

struct HTTP2Context {
  SSL *ssl;
  uint32_t streamId;

  HTTP2Context(SSL *s, uint32_t id) : ssl(s), streamId(id) {}
};

extern const QUIC_API_TABLE *MsQuic;

extern const QUIC_REGISTRATION_CONFIG RegConfig;

extern const QUIC_BUFFER Alpn;

extern const uint16_t UdpPort;

extern const uint64_t IdleTimeoutMs;

extern const uint32_t SendBufferLength;

extern HQUIC Registration;

extern HQUIC Configuration;

extern QUIC_TLS_SECRETS ClientSecrets;

extern const char *SslKeyLogEnvVar;

typedef struct st_hblock_ctx {
  struct lsxpack_header xhdr;
  size_t buf_off;
  char buf[0x1000];
  void *instance_ctx;
  HQUIC stream;
} hblock_ctx_t;

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
  QUIC_CREDENTIAL_CONFIG CredConfig;
  union {
    QUIC_CERTIFICATE_HASH CertHash;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    QUIC_CERTIFICATE_FILE CertFile;
    QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
  };
} QUIC_CREDENTIAL_CONFIG_HELPER;

bool isFlagSet(uint8_t flags, HTTP2Flags flag);

// Helper function to provide program arguments
void PrintUsage();

// Helper functions to look up a command line arguments.
BOOLEAN
GetFlag(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[],
        _In_z_ const char *name);

// Expects argument in  format: -arg:<argument>
_Ret_maybenull_ _Null_terminated_ const char *
GetValue(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[],
         _In_z_ const char *name);

std::string GetValue2(int argc, char *argv[], const std::string &name);

// Helper function to convert a hex character to its decimal value.
uint8_t DecodeHexChar(_In_ char c);

// Helper function to convert a string of hex characters to a byte buffer.
uint32_t DecodeHexBuffer(_In_z_ const char *HexBuffer,
                         _In_ uint32_t OutBufferLen,
                         _Out_writes_to_(OutBufferLen, return)
                             uint8_t *OutBuffer);

void EncodeHexBuffer(_In_reads_(BufferLen) uint8_t *Buffer,
                     _In_ uint8_t BufferLen,
                     _Out_writes_bytes_(2 * BufferLen) char *HexString);

void WriteSslKeyLogFile(_In_z_ const char *FileName,
                        _In_ QUIC_TLS_SECRETS *TlsSecrets);

#endif
