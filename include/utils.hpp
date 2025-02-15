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
// #include "/home/QQueke/Documents/Repositories/ls-qpack/lsqpack.h"
// #include "/home/QQueke/Documents/Repositories/ls-qpack/lsxpack_header.h"
// #include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
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
  TIMEOUT_SECONDS = 60,
  MAX_CONNECTIONS = 100,
  MAX_PENDING_CONNECTIONS = 100,
  HTTP_PORT = 4433,
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
