#include "client.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <unordered_map>

#include "log.hpp"
#include "utils.hpp"

extern std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
    DecodedHeadersMap;

HTTPClient::HTTPClient(int argc, char *argv[]) {
  if (!LoadQUICConfiguration(argc, argv)) {
    exit(EXIT_FAILURE);
  }
}

void HTTPClient::PrintFromServer() { std::cout << "Hello from client\n"; }
HTTPClient::~HTTPClient() { std::cout << "Deconstructing Client" << std::endl; }

unsigned char HTTPClient::LoadQUICConfiguration(int argc, char *argv[]) {
  BOOLEAN Unsecure = GetFlag(argc, argv, "unsecure");

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
    std::ostringstream oss;
    oss << "ConfigurationOpen failed, 0x" << std::hex << Status;
    LogError(oss.str());

    return FALSE;
  }

  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration,
                                                               &CredConfig))) {
    std::ostringstream oss;
    oss << "ConfigurationLoadCredential failed, 0x" << std::hex << Status;
    LogError(oss.str());

    return FALSE;
  }

  return TRUE;
}

int HTTPClient::dhiProcessHeader(void *hblock_ctx,
                                 struct lsxpack_header *xhdr) {
  std::string headerKey(xhdr->buf + xhdr->name_offset, xhdr->name_len);
  std::string headerValue(xhdr->buf + xhdr->val_offset, xhdr->val_len);

  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx;
  HTTPClient *instance = (HTTPClient *)block_ctx->instance_ctx;

  instance->DecodedHeadersMap[block_ctx->stream][headerKey] = headerValue;

  return 0;
}

void HTTPClient::Run(int argc, char *argv[]) {
  QUIC_STATUS Status;
  const char *ResumptionTicketString = NULL;
  const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
  HQUIC Connection = NULL;

  // Allocate a new connection object.
  if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(
                      Registration, HTTPClient::ConnectionCallback, this,
                      &Connection))) {
    printf("ConnectionOpen failed, 0x%x!\n", Status);
    goto Error;
  }

  if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
    //
    // If provided at the command line, set the resumption ticket that can
    // be used to resume a previous session.
    //
    uint8_t ResumptionTicket[10240];
    uint16_t TicketLength = (uint16_t)DecodeHexBuffer(
        ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
    if (QUIC_FAILED(Status = MsQuic->SetParam(
                        Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET,
                        TicketLength, ResumptionTicket))) {
      printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n",
             Status);
      goto Error;
    }
  }

  if (SslKeyLogFile != NULL) {
    if (QUIC_FAILED(
            Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS,
                                      sizeof(ClientSecrets), &ClientSecrets))) {
      printf("SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x%x!\n", Status);
      goto Error;
    }
  }

  // Get the target / server name or IP from the command line.
  const char *Target;
  if ((Target = GetValue(argc, argv, "target")) == NULL) {
    printf("Must specify '-target' argument!\n");
    Status = QUIC_STATUS_INVALID_PARAMETER;
    goto Error;
  }

  printf("[conn][%p] Connecting...\n", Connection);

  // Start the connection to the server.
  if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration,
                                                   QUIC_ADDRESS_FAMILY_UNSPEC,
                                                   Target, UDP_PORT))) {
    printf("ConnectionStart failed, 0x%x!\n", Status);
    goto Error;
  }

Error:

  if (QUIC_FAILED(Status) && Connection != NULL) {
    MsQuic->ConnectionClose(Connection);
  }
}

void HTTPClient::DecQPACKHeaders(HQUIC stream,
                                 std::vector<uint8_t> &encodedHeaders) {
  std::vector<struct lsqpack_dec> dec(1);

  struct lsqpack_dec_hset_if hset_if;
  hset_if.dhi_unblocked = dhiUnblocked;
  hset_if.dhi_prepare_decode = dhiPrepareDecode;
  hset_if.dhi_process_header = HTTPClient::dhiProcessHeader;

  enum lsqpack_dec_opts dec_opts {};
  lsqpack_dec_init(dec.data(), NULL, 0x1000, 0, &hset_if, dec_opts);

  // hblock_ctx_t *blockCtx = (hblock_ctx_t *)malloc(sizeof(hblock_ctx_t));

  std::vector<hblock_ctx_t> blockCtx(1);

  memset(&blockCtx.back(), 0, sizeof(hblock_ctx_t));
  blockCtx.back().instance_ctx = this;
  blockCtx.back().stream = stream;

  const unsigned char *encodedHeadersPtr = encodedHeaders.data();
  size_t totalHeaderSize = encodedHeaders.size();

  enum lsqpack_read_header_status readStatus;

  readStatus =
      lsqpack_dec_header_in(dec.data(), &blockCtx.back(), 100, totalHeaderSize,
                            &encodedHeadersPtr, totalHeaderSize, NULL, NULL);
}

// Parses stream buffer to retrieve headers payload and data payload
void HTTPClient::ParseStreamBuffer(HQUIC Stream,
                                   std::vector<uint8_t> &streamBuffer,
                                   std::string &data) {
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
      case 0x01:  // HEADERS frame
        std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

        {
          std::vector<uint8_t> encodedHeaders(iter, iter + frameLength);

          HTTPClient::DecQPACKHeaders(Stream, encodedHeaders);

          // headers = std::string(iter, iter + frameLength);
        }

        break;

      case 0x00:  // DATA frame
        std::cout << "[strm][" << Stream << "] Received DATA frame\n";
        // Data might have been transmitted over multiple frames
        data += std::string(iter, iter + frameLength);
        break;

      default:  // Unknown frame type
        std::cout << "[strm][" << Stream << "] Unknown frame type: 0x"
                  << std::hex << frameType << std::dec << "\n";
        break;
    }

    iter += frameLength;
  }
  // std::cout << headers << data << "\n";

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < streamBuffer.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << Stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    streamBuffer.end() - iter);
    std::cout << std::endl;
  }
}
