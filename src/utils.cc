#include "utils.h"

#include <msquic.h>
#include <zconf.h>
#include <zlib.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#include "err.h"
#include "log.h"
#include "ssl.h"

// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
// const QUIC_REGISTRATION_CONFIG RegConfig = {"quicsample",
//                                             QUIC_EXECUTION_PROFILE_LOW_LATENCY};

// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
const QUIC_BUFFER Alpn = {sizeof("h3") - 1, (uint8_t *)"h3"};

// The name of the environment variable being
// used to get the path to the ssl key log file.
const char *SslKeyLogEnvVar = "SSLKEYLOGFILE";

// Function to check if a specific flag is set
bool isFlagSet(uint8_t flags, HTTP2Flags flag) { return (flags & flag) != 0; }

// Handling specific SSL errors
std::string GetSSLErrorMessage(int error) {
  std::string errorMessage;

  switch (error) {
  case SSL_ERROR_ZERO_RETURN:
    errorMessage = "SSL connection was closed cleanly.";
    break;
  case SSL_ERROR_WANT_READ:
    errorMessage = "SSL operation would block waiting for read.";
    break;
  case SSL_ERROR_WANT_WRITE:
    errorMessage = "SSL operation would block waiting for write.";
    break;
  case SSL_ERROR_WANT_X509_LOOKUP:
    errorMessage = "Operation blocked waiting for certificate lookup.";
    break;
  case SSL_ERROR_SYSCALL: {
    unsigned long errCode = ERR_peek_last_error();
    std::array<char, 120> errorDetails;
    ERR_error_string_n(errCode, errorDetails.data(), errorDetails.size());
    errorMessage = "System call failure or connection reset. " +
                   std::string(errorDetails.data());
    break;
  }
  case SSL_ERROR_SSL: {
    unsigned long errCode = ERR_peek_last_error();
    std::array<char, 120> errorDetails;
    ERR_error_string_n(errCode, errorDetails.data(), errorDetails.size());
    errorMessage = "Low-level SSL library " + std::string(errorDetails.data());
    break;
  }
  case SSL_ERROR_WANT_CONNECT:
    errorMessage = "SSL operation would block waiting for a connection.";
    break;
  case SSL_ERROR_WANT_ACCEPT:
    errorMessage = "SSL operation would block waiting for an accept.";
    break;
  case SSL_ERROR_WANT_ASYNC:
    errorMessage =
        "SSL operation would block waiting for async job completion.";
    break;
  case SSL_ERROR_WANT_ASYNC_JOB:
    errorMessage =
        "SSL operation would block waiting for async job completion.";
    break;
  case SSL_ERROR_WANT_CLIENT_HELLO_CB:
    errorMessage =
        "SSL operation would block waiting for client hello callback.";
    break;
  case SSL_ERROR_WANT_RETRY_VERIFY:
    errorMessage = "SSL operation requires retry verification.";
    break;
  default: {
    unsigned long errCode = ERR_peek_last_error();
    std::array<char, 120> errorDetails;
    ERR_error_string_n(errCode, errorDetails.data(), errorDetails.size());
    errorMessage = "Unknown SSL error: " + std::string(errorDetails.data());
    break;
  }
  }

  std::cout << errorMessage << std::endl;
  return "(SSL): " + errorMessage;
}

void PrintBytes(void *buf, size_t len) {
  unsigned char *cbuf = (unsigned char *)buf;
  for (size_t i = 0; i < len; ++i) {
    int n = (int)cbuf[i];
    int u = (n >> 4) & 0xf;
    int l = (n) & 0xf;
    printf("%x%x", u, l);
  }
  printf("\n");
}

void PrintUsage() {
  printf("\n"
         "Server runs a simple client or server.\n"
         "\n"
         "Usage:\n"
         "\n"
         "  ./server -client -unsecure -target:{IPAddress|Hostname} "
         "[-ticket:<ticket>]\n"
         "[-requests:requests.txt]\n"
         "  ./server -server -cert_hash:<...>\n"
         "  ./server -server -cert_file:<...> -key_file:<...> "
         "[-password:<...>]\n");
}

// Helper functions to look up a command line arguments.
BOOLEAN
GetFlag(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[],
        _In_z_ const char *name) {
  const size_t nameLen = strlen(name);
  for (int i = 0; i < argc; i++) {
    if (_strnicmp(argv[i] + 1, name, nameLen) == 0 &&
        strlen(argv[i]) == nameLen + 1) {
      return TRUE;
    }
  }
  return FALSE;
}

// Expects argument in  format: -arg:<argument>
_Ret_maybenull_ _Null_terminated_ const char *
GetValue(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[],
         _In_z_ const char *name) {
  const size_t nameLen = strlen(name);
  for (int i = 0; i < argc; i++) {
    if (_strnicmp(argv[i] + 1, name, nameLen) == 0 &&
        strlen(argv[i]) > 1 + nameLen + 1 && *(argv[i] + 1 + nameLen) == ':') {
      return argv[i] + 1 + nameLen + 1;
    }
  }
  return NULL;
}

std::string GetValue2(int argc, char *argv[], const std::string &name) {
  const size_t nameLen = name.length();

  for (int i = 0; i < argc; i++) {
    std::string arg = argv[i];

    // Check if the argument starts with '-' and has the name we're looking for
    if (arg.size() > nameLen + 1 && arg[0] == '-' &&
        arg.substr(1, nameLen) == name && arg[nameLen + 1] == ':') {
      return arg.substr(
          nameLen + 2); // Skip "-name:" and return the value after the colon
    }
  }

  return ""; // Return an empty string if the value isn't found
}

// Helper function to convert a hex character to its decimal value.
uint8_t DecodeHexChar(_In_ char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  return 0;
}

// Helper function to convert a string of hex characters to a byte buffer.
uint32_t DecodeHexBuffer(_In_z_ const char *HexBuffer,
                         _In_ uint32_t OutBufferLen,
                         _Out_writes_to_(OutBufferLen, return)
                             uint8_t *OutBuffer) {
  uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
  if (HexBufferLen > OutBufferLen) {
    return 0;
  }

  for (uint32_t i = 0; i < HexBufferLen; i++) {
    OutBuffer[i] = (DecodeHexChar(HexBuffer[i * 2]) << 4) |
                   DecodeHexChar(HexBuffer[i * 2 + 1]);
  }

  return HexBufferLen;
}

void EncodeHexBuffer(_In_reads_(BufferLen) uint8_t *Buffer,
                     _In_ uint8_t BufferLen,
                     _Out_writes_bytes_(2 * BufferLen) char *HexString) {
#define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
  for (uint8_t i = 0; i < BufferLen; i++) {
    HexString[i * 2] = HEX_TO_CHAR(Buffer[i] >> 4);
    HexString[i * 2 + 1] = HEX_TO_CHAR(Buffer[i] & 0xf);
  }
}

void WriteSslKeyLogFile(_In_z_ const char *FileName,
                        _In_ QUIC_TLS_SECRETS *TlsSecrets) {
  printf("Writing SSLKEYLOGFILE at %s\n", FileName);
  FILE *File = NULL;
#ifdef _WIN32
  File = _fsopen(FileName, "ab", _SH_DENYNO);
#else
  File = fopen(FileName, "ab");
#endif

  if (File == NULL) {
    std::ostringstream oss;
    oss << "Failed to open sslkeylogfile" << FileName;
    LogError(oss.str());
    return;
  }
  if (fseek(File, 0, SEEK_END) == 0 && ftell(File) == 0) {
    fprintf(File, "# TLS 1.3 secrets log file, generated by msquic\n");
  }

  char ClientRandomBuffer[(2 * sizeof(((QUIC_TLS_SECRETS *)0)->ClientRandom)) +
                          1] = {0};

  char TempHexBuffer[(2 * QUIC_TLS_SECRETS_MAX_SECRET_LEN) + 1] = {0};
  if (TlsSecrets->IsSet.ClientRandom) {
    EncodeHexBuffer(TlsSecrets->ClientRandom,
                    (uint8_t)sizeof(TlsSecrets->ClientRandom),
                    ClientRandomBuffer);
  }

  if (TlsSecrets->IsSet.ClientEarlyTrafficSecret) {
    EncodeHexBuffer(TlsSecrets->ClientEarlyTrafficSecret,
                    TlsSecrets->SecretLength, TempHexBuffer);
    fprintf(File, "CLIENT_EARLY_TRAFFIC_SECRET %s %s\n", ClientRandomBuffer,
            TempHexBuffer);
  }

  if (TlsSecrets->IsSet.ClientHandshakeTrafficSecret) {
    EncodeHexBuffer(TlsSecrets->ClientHandshakeTrafficSecret,
                    TlsSecrets->SecretLength, TempHexBuffer);
    fprintf(File, "CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n", ClientRandomBuffer,
            TempHexBuffer);
  }

  if (TlsSecrets->IsSet.ServerHandshakeTrafficSecret) {
    EncodeHexBuffer(TlsSecrets->ServerHandshakeTrafficSecret,
                    TlsSecrets->SecretLength, TempHexBuffer);
    fprintf(File, "SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n", ClientRandomBuffer,
            TempHexBuffer);
  }

  if (TlsSecrets->IsSet.ClientTrafficSecret0) {
    EncodeHexBuffer(TlsSecrets->ClientTrafficSecret0, TlsSecrets->SecretLength,
                    TempHexBuffer);
    fprintf(File, "CLIENT_TRAFFIC_SECRET_0 %s %s\n", ClientRandomBuffer,
            TempHexBuffer);
  }

  if (TlsSecrets->IsSet.ServerTrafficSecret0) {
    EncodeHexBuffer(TlsSecrets->ServerTrafficSecret0, TlsSecrets->SecretLength,
                    TempHexBuffer);
    fprintf(File, "SERVER_TRAFFIC_SECRET_0 %s %s\n", ClientRandomBuffer,
            TempHexBuffer);
  }

  fflush(File);
  fclose(File);
}
