#ifndef UTILS_HPP
#define UTILS_HPP

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

#include "/home/QQueke/Documents/Repositories/ls-qpack/lsqpack.h"
#include "/home/QQueke/Documents/Repositories/ls-qpack/lsxpack_header.h"
#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
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
  HTTP_PORT = 443,
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

void dhiUnblocked(void *hblock_ctx);

struct lsxpack_header *
dhiPrepareDecode(void *hblock_ctx_p, struct lsxpack_header *xhdr, size_t space);

void UQPACKHeadersClient(HQUIC stream, std::vector<uint8_t> &encodedHeaders);

void UQPACKHeadersServer(HQUIC stream, std::vector<uint8_t> &encodedHeaders);

void QPACKHeaders(std::unordered_map<std::string, std::string> &headersMap,
                  std::vector<uint8_t> &encodedHeaders);

std::vector<uint8_t>
BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders);

std::vector<uint8_t> BuildDataFrame(std::string &data);

uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                    const std::vector<uint8_t>::iterator &end);

void EncodeVarint(std::vector<uint8_t> &buffer, uint64_t value);

void ResponseHTTP1ToHTTP3Headers(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headerMap);

void RequestHTTP1ToHTTP3Headers(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headersMap);

// void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
//                              std::string &data);
// void ParseStreamBufferServer(HQUIC Stream, std::vector<uint8_t>
// &streamBuffer,
//                              std::string &headers, std::string &data);

int SendFramesToStream(HQUIC Stream,
                       const std::vector<std::vector<uint8_t>> &frames);
int SendFramesToNewConn(_In_ HQUIC Connection, HQUIC Stream,
                        const std::vector<std::vector<uint8_t>> &frames);

void ParseHTTP3HeadersToMap(
    const std::string &headers,
    std::unordered_map<std::string, std::string> &headersMap);

void ClientSend(_In_ HQUIC Connection);

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

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
  QUIC_CREDENTIAL_CONFIG CredConfig;
  union {
    QUIC_CERTIFICATE_HASH CertHash;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    QUIC_CERTIFICATE_FILE CertFile;
    QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
  };
} QUIC_CREDENTIAL_CONFIG_HELPER;

// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
BOOLEAN
ServerLoadConfiguration(_In_ int argc,
                        _In_reads_(argc) _Null_terminated_ char *argv[]);

// Helper function to load a client configuration. Uses the command line
// arguments to load the credential part of the configuration.
BOOLEAN
ClientLoadConfiguration(BOOLEAN Unsecure);
int SendHTTP1Response(SSL *clientSSL, const std::string &response);
int SendHTTP3Response(HQUIC Stream, const std::string &headers,
                      const std::string &data);

#endif
