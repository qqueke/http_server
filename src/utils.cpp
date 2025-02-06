#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstdlib>
#include <iostream>
#include <array>
#include "utils.hpp"

// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
const QUIC_REGISTRATION_CONFIG RegConfig = {"quicsample",
                                            QUIC_EXECUTION_PROFILE_LOW_LATENCY};

// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
const QUIC_BUFFER Alpn = {sizeof("sample") - 1, (uint8_t *)"sample"};

// The UDP port used by the server side of the protocol.
const uint16_t UdpPort = 4567;

// The default idle timeout period (1 second) used for the protocol.
const uint64_t IdleTimeoutMs = 1000;

//
// The length of buffer sent over the streams in the protocol.
//
const uint32_t SendBufferLength = 100;

// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
const QUIC_API_TABLE *MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC Configuration;

//
// The struct to be filled with TLS secrets
// for debugging packet captured with e.g. Wireshark.
//
QUIC_TLS_SECRETS ClientSecrets = {0};

//
// The name of the environment variable being
// used to get the path to the ssl key log file.
//
const char *SslKeyLogEnvVar = "SSLKEYLOGFILE";

// typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
//   QUIC_CREDENTIAL_CONFIG CredConfig;
//   union {
//     QUIC_CERTIFICATE_HASH CertHash;
//     QUIC_CERTIFICATE_HASH_STORE CertHashStore;
//     QUIC_CERTIFICATE_FILE CertFile;
//     QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
//   };
// } QUIC_CREDENTIAL_CONFIG_HELPER;

void PrintUsage() {
  printf("\n"
         "quicsample runs a simple client or server.\n"
         "\n"
         "Usage:\n"
         "\n"
         "  quicsample.exe -client -unsecure -target:{IPAddress|Hostname} "
         "[-ticket:<ticket>]\n"
         "  quicsample.exe -server -cert_hash:<...>\n"
         "  quicsample.exe -server -cert_file:<...> -key_file:<...> "
         "[-password:<...>]\n");
}

//
// Helper functions to look up a command line arguments.
//
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

//
// Helper function to convert a hex character to its decimal value.
//
uint8_t DecodeHexChar(_In_ char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  return 0;
}

//
// Helper function to convert a string of hex characters to a byte buffer.
//
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
    printf("Failed to open sslkeylogfile %s\n", FileName);
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


//
// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
//
BOOLEAN
ServerLoadConfiguration(_In_ int argc,
                        _In_reads_(argc) _Null_terminated_ char *argv[]) {
  QUIC_SETTINGS Settings = {0};
  //
  // Configures the server's idle timeout.
  //
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;
  //
  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  //
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;
  //
  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  //
  Settings.PeerBidiStreamCount = 1;
  Settings.IsSet.PeerBidiStreamCount = TRUE;

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  const char *Cert;
  const char *KeyFile;
  if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
    //
    // Load the server's certificate from the default certificate store,
    // using the provided certificate hash.
    //
    uint32_t CertHashLen = DecodeHexBuffer(
        Cert, sizeof(Config.CertHash.ShaHash), Config.CertHash.ShaHash);
    if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
      return FALSE;
    }
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
    Config.CredConfig.CertificateHash = &Config.CertHash;

  } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
             (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {

    // Loads the server's certificate from the file.
    const char *Password = GetValue(argc, argv, "password");
    if (Password != NULL) {
      Config.CertFileProtected.CertificateFile = (char *)Cert;
      Config.CertFileProtected.PrivateKeyFile = (char *)KeyFile;
      Config.CertFileProtected.PrivateKeyPassword = (char *)Password;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
      Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
    } else {
      Config.CertFile.CertificateFile = (char *)Cert;
      Config.CertFile.PrivateKeyFile = (char *)KeyFile;
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
      Config.CredConfig.CertificateFile = &Config.CertFile;
    }

  } else {
    printf("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and "
           "optionally 'password')]!\n");
    return FALSE;
  }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    printf("ConfigurationOpen failed, 0x%x!\n", Status);
    return FALSE;
  }

  //
  // Loads the TLS credential part of the configuration.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig))) {
    printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
    return FALSE;
  }

  return TRUE;
}

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);
  switch (Event->Type) {
  case QUIC_STREAM_EVENT_SEND_COMPLETE:
    //
    // A previous StreamSend call has completed, and the context is being
    // returned back to the app.
    //

    free(Event->SEND_COMPLETE.ClientContext);
    printf("[strm][%p] Data sent\n", Stream);
    break;
  case QUIC_STREAM_EVENT_RECEIVE:
    //
    // Data was received from the peer on the stream.
    //
    printf("[strm][%p] Data received\n", Stream);

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

      // Print received data (assuming text)
      fwrite(buffer->Buffer, 1, buffer->Length, stdout);
      printf("\n");
    }
    printf("\n");

    // RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);

    // for (uint32_t i = 0;
    //      i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
    //   printf("%.2X",
    //          (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
    // }
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    //
    // The peer gracefully shut down its send direction of the stream.
    //
    printf("[strm][%p] Peer aborted\n", Stream);
    break;
  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    //
    // The peer aborted its send direction of the stream.
    //
    printf("[strm][%p] Peer shut down\n", Stream);
    break;
  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
    //
    // Both directions of the stream have been shut down and MsQuic is done
    // with the stream. It can now be safely cleaned up.
    //
    printf("[strm][%p] All done\n", Stream);
    if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
      MsQuic->StreamClose(Stream);
    }
    break;
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

int SendData(_In_ HQUIC Connection, HQUIC Stream, const std::string &response) {
  QUIC_STATUS Status;
  uint8_t *SendBufferRaw;
  QUIC_BUFFER *SendBuffer;

  SendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + response.size());

  if (SendBufferRaw == NULL) {
    printf("SendBuffer allocation failed!\n");
    Status = QUIC_STATUS_OUT_OF_MEMORY;
    if (QUIC_FAILED(Status)) {
      MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                 0);
      return -1;
    }
  }
  SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
  SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
  SendBuffer->Length = response.size();

  memcpy(SendBuffer->Buffer, response.c_str(), response.size());

  printf("[strm][%p] Sending data...\n", Stream);

  // Sends the buffer over the stream. Note the FIN flag is passed along with
  // the buffer. This indicates this is the last buffer on the stream and the
  // the stream is shut down (in the send direction) immediately after.
  if (QUIC_FAILED(Status = MsQuic->StreamSend(
                      Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
    printf("StreamSend failed, 0x%x!\n", Status);
    free(SendBufferRaw);
    if (QUIC_FAILED(Status)) {
      MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                 0);
      return -1;
    }
  }
  return response.size();
}

void ClientSend(_In_ HQUIC Connection) {
  QUIC_STATUS Status;
  // uint8_t *SendBufferRaw;
  // QUIC_BUFFER *SendBuffer;

  //
  // Create/allocate a new bidirectional stream. The stream is just allocated
  // and no QUIC stream identifier is assigned until it's started.
  //

  std::array<HQUIC, 5> Streams{};
  int i = 0;
  for (HQUIC &Stream : Streams) {

    std::cout << "Stream: " << i++ << "\n";
    if (QUIC_FAILED(
            Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE,
                                        ClientStreamCallback, NULL, &Stream))) {
      printf("StreamOpen failed, 0x%x!\n", Status);
      if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return;
      }
    }

    printf("[strm][%p] Starting Stream...\n", Stream);

    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    if (QUIC_FAILED(Status = MsQuic->StreamStart(
                        Stream, QUIC_STREAM_START_FLAG_NONE))) {
      printf("StreamStart failed, 0x%x!\n", Status);
      MsQuic->StreamClose(Stream);
      if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return;
      }
    }

    std::string response = "HTTP/1.1 200 OK\r\n";
    response += std::to_string(i);
    if (SendData(Connection, Stream, response) == -1) {
      return;
    }
  }
}

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ClientConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);

  if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
    const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
    if (SslKeyLogFile != NULL) {
      WriteSslKeyLogFile(SslKeyLogFile, &ClientSecrets);
    }
  }

  switch (Event->Type) {
  case QUIC_CONNECTION_EVENT_CONNECTED:
    //
    // The handshake has completed for the connection.
    //
    printf("[conn][%p] Connected\n", Connection);
    ClientSend(Connection);
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    //
    // The connection has been shut down by the transport. Generally, this
    // is the expected way for the connection to shut down with this
    // protocol, since we let idle timeout kill the connection.
    //
    if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
        QUIC_STATUS_CONNECTION_IDLE) {
      printf("[conn][%p] Successfully shut down on idle.\n", Connection);
    } else {
      printf("[conn][%p] Shut down by transport, 0x%x\n", Connection,
             Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
    }
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
    //
    // The connection was explicitly shut down by the peer.
    //
    printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
           (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
    break;
  case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
    //
    // The connection has completed the shutdown process and is ready to be
    // safely cleaned up.
    //
    printf("[conn][%p] All done\n", Connection);
    if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
      MsQuic->ConnectionClose(Connection);
    }
    break;
  case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
    //
    // A resumption ticket (also called New Session Ticket or NST) was
    // received from the server.
    //
    printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection,
           Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
    // for (uint32_t i = 0;
    //      i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
    //   printf("%.2X",
    //          (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
    // }
    // printf("\n");
    break;
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

//
// Helper function to load a client configuration.
//
BOOLEAN
ClientLoadConfiguration(BOOLEAN Unsecure) {
  QUIC_SETTINGS Settings = {0};
  //
  // Configures the client's idle timeout.
  //
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  //
  // Configures a default client configuration, optionally disabling
  // server certificate validation.
  //
  QUIC_CREDENTIAL_CONFIG CredConfig;
  memset(&CredConfig, 0, sizeof(CredConfig));
  CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
  if (Unsecure) {
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    printf("ConfigurationOpen failed, 0x%x!\n", Status);
    return FALSE;
  }

  //
  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration,
                                                               &CredConfig))) {
    printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
    return FALSE;
  }

  return TRUE;
}
