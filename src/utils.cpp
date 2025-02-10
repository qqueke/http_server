#include "utils.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include "/home/QQueke/Documents/Repositories/ls-qpack/lsqpack.h"
#include "/home/QQueke/Documents/Repositories/ls-qpack/lsxpack_header.h"
#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"

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

// The length of buffer sent over the streams in the protocol.
const uint32_t SendBufferLength = 100;

// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
const QUIC_API_TABLE *MsQuic;

// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
HQUIC Registration;

// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
HQUIC Configuration;

// The struct to be filled with TLS secrets
// for debugging packet captured with e.g. Wireshark.
QUIC_TLS_SECRETS ClientSecrets = {0};

// The name of the environment variable being
// used to get the path to the ssl key log file.
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

#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

typedef struct st_hblock_ctx {
  struct lsxpack_header xhdr;
  size_t buf_off;
  char buf[0x1000];
} hblock_ctx_t;

void dhi_unblocked(void *hblock_ctx) { printf("dhi_unblocked\n"); }

struct lsxpack_header *dhi_prepare_decode(void *hblock_ctx_p,
                                          struct lsxpack_header *xhdr,
                                          size_t space) {
  printf("dhi_prepare_decode: xhdr=%lu, space=%lu\n", (size_t)xhdr, space);
  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx_p;

  if (xhdr != NULL) {
    xhdr->val_len = space;
  } else {
    lsxpack_header_prepare_decode(&block_ctx->xhdr, block_ctx->buf,
                                  block_ctx->buf_off, space);
  }
  return &block_ctx->xhdr;
  ;
}

int dhi_process_header(void *hblock_ctx, struct lsxpack_header *xhdr) {
  printf("dhi_process_header: xhdr=%lu\n", (size_t)xhdr);
  printf("%.*s: %.*s\n", xhdr->name_len, (xhdr->buf + xhdr->name_offset),
         xhdr->val_len, (xhdr->buf + xhdr->val_offset));
  return 0;
}

void print_bytes(void *buf, size_t len) {
  unsigned char *cbuf = (unsigned char *)buf;
  for (size_t i = 0; i < len; ++i) {
    int n = (int)cbuf[i];
    int u = (n >> 4) & 0xf;
    int l = (n) & 0xf;
    printf("%x%x", u, l);
  }
  printf("\n");
}

void QPACKHeaders(
    const std::unordered_map<std::string, std::string> &headersMap,
    std::vector<uint8_t> &encodedHeaders) {
  // Prepare encoding context for QPACK (Header encoding for QUIC)
  struct lsqpack_enc *enc = (lsqpack_enc *)malloc(sizeof(struct lsqpack_enc));
  size_t buf_size = 1024;
  unsigned char *buffer = (unsigned char *)malloc(buf_size);

  lsqpack_enc_opts enc_opts{};

  int ret = lsqpack_enc_init(enc, stdout, 0x1000, 0x1000, 0, enc_opts, buffer,
                             &buf_size);

  if (ret != 0) {
    std::cerr << "Error initializing encoder." << std::endl;
    return;
  }

  // Iterate through the headersMap and encode each header
  for (const auto &header : headersMap) {
    const std::string &name = header.first;
    const std::string &value = header.second;

    struct lsxpack_header xhdr;
    lsxpack_header_set_offset2(&xhdr, name.c_str(), 0, name.length(),
                               value.length(), 10); // example offset values

    size_t enc_sz = 1024;
    unsigned char *enc_buf = (unsigned char *)malloc(enc_sz);
    size_t hdr_sz = 1024;
    unsigned char *hdr_buf = (unsigned char *)malloc(hdr_sz);

    lsqpack_enc_flags enc_flags;

    enum lsqpack_enc_status enc_status = lsqpack_enc_encode(
        enc, enc_buf, &enc_sz, hdr_buf, &hdr_sz, &xhdr, enc_flags);

    // if (enc_status != LSQPACK_ENC_STATUS_OK) {
    //   std::cerr << "Error encoding header: " << name << std::endl;
    //   continue;
    // }

    encodedHeaders.insert(encodedHeaders.end(), enc_buf, enc_buf + enc_sz);
    encodedHeaders.insert(encodedHeaders.end(), hdr_buf, hdr_buf + hdr_sz);
    // Print the encoded header for debugging

    // std::cout << "Encoded header: " << name << ": " << value << std::endl;
    // print_bytes(enc_buf, enc_sz);
    // print_bytes(hdr_buf, hdr_sz);
  }

  // Clean up encoder resources
  free(buffer);
  free(enc);
}

void QUNPACKHeaders(const unsigned char *encoded_data, size_t data_size,
                    std::unordered_map<std::string, std::string> &headersMap) {
  struct lsqpack_dec *dec =
      (struct lsqpack_dec *)malloc(sizeof(struct lsqpack_dec));
  struct lsqpack_dec_hset_if hset_if;
  hset_if.dhi_unblocked = dhi_unblocked;
  hset_if.dhi_prepare_decode = dhi_prepare_decode;
  hset_if.dhi_process_header = dhi_process_header;
  lsqpack_dec_opts dec_opts{};
  lsqpack_dec_init(dec, stdout, 0x1000, 0, &hset_if, dec_opts);

  size_t processed_size = 0;
  const unsigned char *data_ptr = encoded_data;

  // Decode the headers from the encoded buffer
  while (processed_size < data_size) {
    enum lsqpack_read_header_status read_status = lsqpack_dec_header_in(
        dec, NULL, 0, data_size - processed_size, &data_ptr,
        data_size - processed_size, NULL, NULL);

    // if (read_status != LSQPACK_READ_HEADER_OK) {
    //   std::cerr << "Error decoding header." << std::endl;
    //   break;
    // }

    // Example: Here we assume headers are processed one by one
    const struct lsxpack_header *xhdr =
        &((hblock_ctx_t *)NULL)
             ->xhdr; // Access the header (this needs proper structure casting)

    std::string name(reinterpret_cast<char *>(xhdr->buf + xhdr->name_offset),
                     xhdr->name_len);
    std::string value(reinterpret_cast<char *>(xhdr->buf + xhdr->val_offset),
                      xhdr->val_len);

    // Insert the decoded header into the map
    headersMap[name] = value;

    processed_size += xhdr->val_len + xhdr->name_len + 2;
  }

  // Clean up decoder resources
  free(dec);
}

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

void EncodeVarint(std::vector<uint8_t> &buffer, uint64_t value) {
  if (value <= 63) { // Fit in 1 byte
    buffer.push_back(static_cast<uint8_t>(value));
  } else if (value <= 16383) { // Fit in 2 bytes
    buffer.push_back(
        static_cast<uint8_t>((value >> 8) | 0x40));       // Set prefix 01
    buffer.push_back(static_cast<uint8_t>(value & 0xFF)); // Remaining 8 bits
  } else if (value <= 1073741823) {                       // Fit in 4 bytes
    buffer.push_back(
        static_cast<uint8_t>((value >> 24) | 0x80)); // Set prefix 10
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
  } else if (value <= 4611686018427387903) { // Fit in 8 bytes
    buffer.push_back(
        static_cast<uint8_t>((value >> 56) | 0xC0)); // Set prefix 11
    buffer.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
  }
}

uint64_t ReadVarint(std::vector<uint8_t>::iterator &iter,
                    const std::vector<uint8_t>::iterator &end) {
  // Check if there's enough data for at least the first byte
  if (iter + 1 >= end) {
    std::cout << "Error: Buffer overflow in ReadVarint\n";
    return -1; // or some error value
  }

  // Read the first byte
  uint64_t value = *iter++;
  uint8_t prefix =
      value >> 6; // Get the prefix to determine the length of the varint
  size_t length = 1 << prefix; // 1, 2, 4, or 8 bytes

  value &= 0x3F; // Mask out the 2 most significant bits

  // Check if we have enough data for the full varint
  if (iter + length - 1 >= end) {
    std::cout << "Error: Not enough data in buffer for full varint\n";
    return -1; // or some error value
  }

  // Read the remaining bytes of the varint
  for (size_t i = 1; i < length; ++i) {
    value = (value << 8) | *iter++;
  }

  return value;
}

std::vector<uint8_t> BuildDataFrame(std::string &data) {
  // Construct the frame header for Headers
  uint8_t frameType = 0x00; // 0x00 for DATA frame
  size_t payloadLength = data.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType);
  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength);

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payloadLength);
  memcpy(framePayload.data(), data.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> dataFrame(totalFrameSize);
  memcpy(dataFrame.data(), frameHeader.data(), frameHeader.size());
  memcpy(dataFrame.data() + frameHeader.size(), framePayload.data(),
         payloadLength);

  return dataFrame;
}

std::vector<uint8_t> BuildHeaderFrame(std::string &compressedHeaders) {
  // Construct the frame header for Headers
  uint8_t frameType = 0x01; // 0x01 for HEADERS frame
  size_t payloadLength = compressedHeaders.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType);
  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength);

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payloadLength);
  memcpy(framePayload.data(), compressedHeaders.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> headerFrame(totalFrameSize);
  memcpy(headerFrame.data(), frameHeader.data(), frameHeader.size());
  memcpy(headerFrame.data() + frameHeader.size(), framePayload.data(),
         payloadLength);

  return headerFrame;
}

std::string RequestHTTP1ToHTTP3Headers(const std::string &http1Headers) {
  std::istringstream stream(http1Headers);
  std::string line;
  std::string key{};
  std::string value{};
  std::vector<std::pair<std::string, std::string>> headers;

  // Read the first line (status line in HTTP/1.1)
  while (std::getline(stream, line, '\n')) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    size_t firstSpace = line.find(' ');
    if (firstSpace != std::string::npos) {
      // If we find a second space it is the status header
      size_t secondSpace = line.find(' ', firstSpace + 1);
      if (secondSpace != std::string::npos) {
        key = ":method";
        value = line.substr(0, firstSpace);
        headers.emplace_back(key, value);

        key = ":scheme";
        value = "https";
        headers.emplace_back(key, value);

        key = ":path";
        value = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        headers.emplace_back(key, value);

      } else {
        key = line.substr(0, firstSpace - 1);
        value = line.substr(firstSpace + 1);

        // Remove "Connection" header
        if (key != "Connection")
          headers.emplace_back(key, value);
      }
    }
  }

  // Construct HTTP/3 headers
  std::string http3Headers;
  for (const auto &entry : headers) {
    http3Headers += entry.first + ": " + entry.second + "\r\n";
  }

  return http3Headers;
}

void ParseHTTP3HeadersToMap(
    const std::string &headers,
    std::unordered_map<std::string, std::string> &headersMap) {
  std::istringstream headersStream(headers);
  std::string line;

  while (std::getline(headersStream, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    // Find first occurrence of ": "
    size_t pos = line.find(": ");
    if (pos != std::string::npos) {
      std::string key = line.substr(0, pos);
      std::string value = line.substr(pos + 2);
      headersMap[key] = value;
    }
  }
}

std::string ResponseHTTP1ToHTTP3Headers(const std::string &http1Headers) {
  std::istringstream stream(http1Headers);
  std::string line;
  std::string key{};
  std::string value{};
  std::vector<std::pair<std::string, std::string>> headers;

  // Read the first line (status line in HTTP/1.1)
  while (std::getline(stream, line, '\n')) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    size_t firstSpace = line.find(' ');
    if (firstSpace != std::string::npos) {
      // If we find a second space it is the status header
      size_t secondSpace = line.find(' ', firstSpace + 1);
      if (secondSpace != std::string::npos) {
        key = ":status";
        value = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        headers.emplace_back(key, value);

      } else {
        key = line.substr(0, firstSpace - 1);
        value = line.substr(firstSpace + 1);

        // Remove "Connection" header
        if (key != "Connection")
          headers.emplace_back(key, value);
      }
    }
  }

  // Construct HTTP/3 headers
  std::string http3Headers;
  for (const auto &entry : headers) {
    http3Headers += entry.first + ": " + entry.second + "\r\n";
  }

  return http3Headers;
}

// Parses stream buffer to retrieve headers payload and data payload
void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
                       std::string &headers, std::string &data) {
  auto iter = streamBuffer.begin();

  while (iter < streamBuffer.end()) {
    // Ensure we have enough data for a frame (frameType + frameLength)
    if (std::distance(iter, streamBuffer.end()) < 3) {
      std::cout << "Error: Bad frame format (Not enough data)\n";
      break;
    }

    // Read the frame type
    uint64_t frameType = ReadVarint(iter, streamBuffer.end());

    // Read the frame length
    uint64_t frameLength = ReadVarint(iter, streamBuffer.end());

    // Ensure the payload doesn't exceed the bounds of the buffer
    if (std::distance(iter, streamBuffer.end()) < frameLength) {
      std::cout << "Error: Payload exceeds buffer bounds\n";
      break;
    }

    // Handle the frame based on the type
    switch (frameType) {
    case 0x01: // HEADERS frame
      std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";
      headers = std::string(iter, iter + frameLength);
      break;

    case 0x00: // DATA frame
      std::cout << "[strm][" << Stream << "] Received DATA frame\n";
      // Data might have been transmitted over multiple frames
      data += std::string(iter, iter + frameLength);
      break;

    default: // Unknown frame type
      std::cout << "[strm][" << Stream << "] Unknown frame type: 0x" << std::hex
                << frameType << std::dec << "\n";
      break;
    }

    iter += frameLength;
  }
  std::cout << headers << data << "\n";

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < streamBuffer.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << Stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    streamBuffer.end() - iter);
    std::cout << std::endl;
  }
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

// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
BOOLEAN
ServerLoadConfiguration(_In_ int argc,
                        _In_reads_(argc) _Null_terminated_ char *argv[]) {
  QUIC_SETTINGS Settings = {0};

  // Configures the server's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;

  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  Settings.PeerBidiStreamCount = 2;
  Settings.IsSet.PeerBidiStreamCount = TRUE;
  Settings.PeerUnidiStreamCount = 2;
  Settings.IsSet.PeerUnidiStreamCount = TRUE;

  // Settings.StreamMultiReceiveEnabled = TRUE;

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  const char *Cert;
  const char *KeyFile;
  if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
    // Load the server's certificate from the default certificate store,
    // using the provided certificate hash.

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

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    printf("ConfigurationOpen failed, 0x%x!\n", Status);
    return FALSE;
  }

  // Loads the TLS credential part of the configuration.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig))) {
    printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
    return FALSE;
  }

  return TRUE;
}

int SendFramesToStream(HQUIC Stream,
                       const std::vector<std::vector<uint8_t>> &frames) {
  QUIC_STATUS Status;
  uint8_t *SendBufferRaw;
  QUIC_BUFFER *SendBuffer;

  for (auto &frame : frames) {
    // const std::vector<uint8_t>& frame = frames[i];

    SendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + frame.size());

    if (SendBufferRaw == NULL) {
      printf("SendBuffer allocation failed!\n");
      Status = QUIC_STATUS_OUT_OF_MEMORY;
      if (QUIC_FAILED(Status)) {
        std::cout << "Shutting down connection..." << std::endl;

        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);

        return -1;
      }
    }

    SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = frame.size();

    memcpy(SendBuffer->Buffer, frame.data(), frame.size());

    printf("[strm][%p] Sending data...\n", Stream);

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1,
                                                (&frame == &frames.back())
                                                    ? QUIC_SEND_FLAG_FIN
                                                    : QUIC_SEND_FLAG_DELAY_SEND,
                                                SendBuffer))) {
      printf("StreamSend failed, 0x%x!\n", Status);
      free(SendBufferRaw);
      if (QUIC_FAILED(Status)) {
        std::cout << "Shutting down connection..." << std::endl;

        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);

        return -1;
      }
    }
  }
  return 0;
}

int SendFramesToNewConn(_In_ HQUIC Connection, HQUIC Stream,
                        const std::vector<std::vector<uint8_t>> &frames) {
  QUIC_STATUS Status;
  uint8_t *SendBufferRaw;
  QUIC_BUFFER *SendBuffer;

  for (auto &frame : frames) {
    // const std::vector<uint8_t>& frame = frames[i];

    SendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + frame.size());

    if (SendBufferRaw == NULL) {
      printf("SendBuffer allocation failed!\n");
      Status = QUIC_STATUS_OUT_OF_MEMORY;
      if (QUIC_FAILED(Status)) {
        std::cout << "Shutting down connection..." << std::endl;
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return -1;
      }
    }

    SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = frame.size();

    memcpy(SendBuffer->Buffer, frame.data(), frame.size());

    printf("[strm][%p] Sending data...\n", Stream);

    std::cout << "Attempting to send without closing\n";

    // Delay on sending the last frame
    // if (&frame == &frames.back()) {
    //   std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    // }

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1,
                                                (&frame == &frames.back())
                                                    ? QUIC_SEND_FLAG_FIN
                                                    : QUIC_SEND_FLAG_DELAY_SEND,
                                                SendBuffer))) {
      printf("StreamSend failed, 0x%x!\n", Status);
      free(SendBufferRaw);
      if (QUIC_FAILED(Status)) {
        std::cout << "Shutting down connection..." << std::endl;
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return -1;
      }
    }
  }
  return frames.size();
}

//
// Helper function to load a client configuration.
//
BOOLEAN
ClientLoadConfiguration(BOOLEAN Unsecure) {
  QUIC_SETTINGS Settings = {0};
  // Configures the client's idle timeout.
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;
  Settings.StreamMultiReceiveEnabled = TRUE;

  // Configures a default client configuration, optionally disabling
  // server certificate validation.
  QUIC_CREDENTIAL_CONFIG CredConfig;
  memset(&CredConfig, 0, sizeof(CredConfig));
  CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
  if (Unsecure) {
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL,
                      &Configuration))) {
    printf("ConfigurationOpen failed, 0x%x!\n", Status);
    return FALSE;
  }

  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration,
                                                               &CredConfig))) {
    printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
    return FALSE;
  }

  return TRUE;
}
