#ifndef UTILS_HPP
#define UTILS_HPP
#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
#include <cstdio>
#include <cstdlib>
#include <string>


#define _CRT_SECURE_NO_WARNINGS 1
#define UDP_PORT 4567
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

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

// typedef struct QUIC_CREDENTIAL_CONFIG_HELPER ;

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

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event);

int SendData(_In_ HQUIC Connection, HQUIC Stream, const std::string &response);

void ClientSend(_In_ HQUIC Connection);

// The clients's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ClientConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event);

// Helper function to load a client configuration.
BOOLEAN
ClientLoadConfiguration(BOOLEAN Unsecure);

#endif
