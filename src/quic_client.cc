// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/quic_client.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/http3_frame_builder.h"
#include "../include/http3_frame_handler.h"
#include "../include/log.h"

static std::vector<uint8_t> ReadResumptionTicketFromFile() {
  const std::string filename = "ticket";  // Hardcoded filename
  uint32_t ticketLength = 0;

  // Open the file in binary mode
  std::ifstream inFile(filename, std::ios::binary);

  if (inFile.is_open()) {
    // Read the length of the resumption ticket
    inFile.read(reinterpret_cast<char *>(&ticketLength), sizeof(ticketLength));
    uint32_t hostOrder = ntohl(ticketLength);

    // Read the ticket data into a vector of bytes
    std::vector<uint8_t> ticketData(hostOrder);
    inFile.read(reinterpret_cast<char *>(ticketData.data()), hostOrder);

    inFile.close();

    return ticketData;
  }

  std::cout << "Failed to open file for reading: " << filename << std::endl;
  return {};
}

static void ValidatePseudoHeadersTmp(
    std::unordered_map<std::string, std::string> &headers_map) {
  static constexpr std::array<std::string_view, 3> requiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : requiredHeaders) {
    if (headers_map.find(std::string(header)) == headers_map.end()) {
      // LogError("Failed to validate pseudo-headers (missing header field)");
      headers_map[":method"] = "BR";
      headers_map[":path"] = "";
      return;
    }
  }
}

const QUIC_API_TABLE *QuicClient::ms_quic_ = nullptr;
HQUIC QuicClient::config_ = nullptr;

QuicClient::QuicClient(
    int argc, char *argv[],
    const std::vector<std::pair<std::string, std::string>> &requests)
    : requests_(requests), status_(0), secrets_(0) {
  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(status_ = MsQuicOpen2(&ms_quic_))) {
    printf("MsQuicOpen2 failed, 0x%x!\n", status_);
    if (ms_quic_ != nullptr) {
      if (config_ != nullptr) {
        ms_quic_->ConfigurationClose(config_);
      }
      if (registration_ != nullptr) {
        // This will block until all outstanding child objects have been
        // closed.
        ms_quic_->RegistrationClose(registration_);
      }
      MsQuicClose(ms_quic_);
    }

    exit(EXIT_FAILURE);
  }

  // Create a registration for the app's connections.
  if (QUIC_FAILED(
          status_ = ms_quic_->RegistrationOpen(&kRegConfig, &registration_))) {
    printf("RegistrationOpen failed, 0x%x!\n", status_);
    if (ms_quic_ != nullptr) {
      if (config_ != nullptr) {
        ms_quic_->ConfigurationClose(config_);
      }
      if (registration_ != nullptr) {
        // This will block until all outstanding child objects have been
        // closed.
        ms_quic_->RegistrationClose(registration_);
      }
      MsQuicClose(ms_quic_);
    }
    exit(EXIT_FAILURE);
  }

  codec_ = std::make_shared<QpackCodec>(ms_quic_);

  transport_ = std::make_shared<QuicTransport>(ms_quic_);

  frame_builder_ = std::make_shared<Http3FrameBuilder>();

  if (!LoadConfiguration(argc, argv)) {
    exit(EXIT_FAILURE);
  }
}

QuicClient::~QuicClient() {}

int QuicClient::LoadConfiguration(int argc, char *argv[]) {
  BOOLEAN unsecure = GetFlag(argc, argv, "unsecure");

  QUIC_SETTINGS settings = {0};
  // Configures the client's idle timeout.
  settings.IdleTimeoutMs = 1000;
  settings.IsSet.IdleTimeoutMs = TRUE;
  // Settings.StreamMultiReceiveEnabled = TRUE;

  // Configures a default client configuration, optionally disabling
  // server certificate validation.
  QUIC_CREDENTIAL_CONFIG cred_config;
  memset(&cred_config, 0, sizeof(cred_config));
  cred_config.Type = QUIC_CREDENTIAL_TYPE_NONE;
  cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
  if (unsecure) {
    std::cout << "Unsecure connection\n";
    cred_config.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(status = ms_quic_->ConfigurationOpen(
                      registration_, &Alpn, 1, &settings, sizeof(settings),
                      NULL, &config_))) {
    std::ostringstream oss;
    oss << "ConfigurationOpen failed, 0x" << std::hex << status;
    LogError(oss.str());

    return FALSE;
  }

  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  if (QUIC_FAILED(status = ms_quic_->ConfigurationLoadCredential(
                      config_, &cred_config))) {
    std::ostringstream oss;
    oss << "ConfigurationLoadCredential failed, 0x" << std::hex << status
        << std::dec;
    LogError(oss.str());

    return FALSE;
  }

  return TRUE;
}

void QuicClient::Run(int argc, char *argv[]) {
  QUIC_STATUS Status;
  HQUIC Connection = NULL;

  // Allocate a new connection object.
  if (QUIC_FAILED(Status = ms_quic_->ConnectionOpen(
                      registration_, QuicClient::ConnectionCallback, this,
                      &Connection))) {
    printf("ConnectionOpen failed, 0x%x!\n", Status);
    if (QUIC_FAILED(Status) && Connection != NULL) {
      ms_quic_->ConnectionClose(Connection);
    }
    exit(EXIT_FAILURE);
  }

  const char *ResumptionTicketString = NULL;

  std::vector<uint8_t> ticket;
  if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
    // If provided at the command line, set the resumption ticket that can
    // be used to resume a previous session.

    std::cout << "ResumptionTicketString len: "
              << strlen(ResumptionTicketString) << "\n";
    uint8_t ResumptionTicket[10240];
    uint16_t TicketLength = static_cast<uint16_t>(DecodeHexBuffer(
        ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket));
    if (QUIC_FAILED(Status = ms_quic_->SetParam(
                        Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET,
                        TicketLength, ResumptionTicket))) {
      printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n",
             Status);
      if (QUIC_FAILED(Status) && Connection != NULL) {
        ms_quic_->ConnectionClose(Connection);
      }
      exit(EXIT_FAILURE);
    }
  } else if (!(ticket = ReadResumptionTicketFromFile()).empty()) {
    std::cout << "Found ticket file\n";

    if (QUIC_FAILED(Status = ms_quic_->SetParam(
                        Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET,
                        ticket.size(), ticket.data()))) {
      printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n",
             Status);
      if (QUIC_FAILED(Status) && Connection != NULL) {
        ms_quic_->ConnectionClose(Connection);
      }
      exit(EXIT_FAILURE);
    }
  }

  const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
  if (SslKeyLogFile != NULL) {
    if (QUIC_FAILED(Status = ms_quic_->SetParam(Connection,
                                                QUIC_PARAM_CONN_TLS_SECRETS,
                                                sizeof(secrets_), &secrets_))) {
      printf("SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x%x!\n", Status);
      if (QUIC_FAILED(Status) && Connection != NULL) {
        ms_quic_->ConnectionClose(Connection);
      }
      exit(EXIT_FAILURE);
    }
  }

  // Get the target / server name or IP from the command line.
  const char *Target;
  if ((Target = GetValue(argc, argv, "target")) == NULL) {
    printf("Must specify '-target' argument!\n");
    Status = QUIC_STATUS_INVALID_PARAMETER;
    if (QUIC_FAILED(Status) && Connection != NULL) {
      ms_quic_->ConnectionClose(Connection);
    }
    exit(EXIT_FAILURE);
  }

  printf("[conn][%p] Connecting...\n", Connection);

  // Start the connection to the server.
  if (QUIC_FAILED(Status = ms_quic_->ConnectionStart(Connection, config_,
                                                     QUIC_ADDRESS_FAMILY_UNSPEC,
                                                     Target, UDP_PORT))) {
    printf("ConnectionStart failed, 0x%x!\n", Status);
    if (QUIC_FAILED(Status) && Connection != NULL) {
      ms_quic_->ConnectionClose(Connection);
    }
    exit(EXIT_FAILURE);
  }
}

void QuicClient::QuicSend(_In_ HQUIC Connection, void *Context) {
  QuicClient *client = reinterpret_cast<QuicClient *>(Context);
  QUIC_STATUS Status;

  int i = 0;
  std::vector<HQUIC> Streams(client->requests_.size());

  for (auto &[headers, body] : client->requests_) {
    HQUIC &Stream = Streams[i++];

    // Create/allocate a new bidirectional stream. The stream is just
    // allocated and no QUIC stream identifier is assigned until it's
    // started.
    // QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL
    if (QUIC_FAILED(Status = ms_quic_->StreamOpen(
                        Connection, QUIC_STREAM_OPEN_FLAG_NONE,
                        QuicClient::StreamCallback, Context, &Stream))) {
      printf("StreamOpen failed, 0x%x!\n", Status);
      if (QUIC_FAILED(Status)) {
        ms_quic_->ConnectionShutdown(Connection,
                                     QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
      }
    }

#ifdef QUIC_DEBUG
    printf("[strm][%p] Starting Stream...\n", Stream);
#endif
    // Starts the stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    // QUIC_STREAM_START_FLAG_NONE
    // QUIC_STREAM_START_FLAG_IMMEDIATE
    if (QUIC_FAILED(Status = ms_quic_->StreamStart(
                        Stream, QUIC_STREAM_START_FLAG_NONE))) {
      printf("StreamStart failed, 0x%x!\n", Status);

      ms_quic_->StreamClose(Stream);
      if (QUIC_FAILED(Status)) {
        ms_quic_->ConnectionShutdown(Connection,
                                     QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return;
      }
    }

    {
      HeaderParser parser;
      std::unordered_map<std::string, std::string> headers_map =
          parser.ConvertRequestToPseudoHeaders(headers);

      std::vector<uint8_t> encoded_headers;

      uint64_t stream_id{};
      uint32_t len = static_cast<uint32_t>(sizeof(stream_id));
      if (QUIC_FAILED(ms_quic_->GetParam(Stream, QUIC_PARAM_STREAM_ID, &len,
                                         &stream_id))) {
        LogError("Failed to acquire stream id");
      }

      client->codec_->Encode(&Stream, headers_map, encoded_headers);
      // Put header frame and data frames in frames response
      std::vector<std::vector<uint8_t>> frames;

      frames.emplace_back(client->frame_builder_->BuildFrame(Frame::HEADERS, 0,
                                                             encoded_headers));

      frames.emplace_back(
          client->frame_builder_->BuildFrame(Frame::DATA, 0, {}, body));

      client->transport_->SendBatch(Stream, frames);
    }
  }
}

// The clients's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    QuicClient::StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                               _Inout_ QUIC_STREAM_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);

  QuicClient *client = reinterpret_cast<QuicClient *>(Context);

  switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.

      // We set the send context to be the pointer that we can latter free
      free(Event->SEND_COMPLETE.ClientContext);

#ifdef QUIC_DEBUG
      printf("[strm][%p] Data sent\n", Stream);
#endif
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      // Data was received from the peer on the stream.
#ifdef QUIC_DEBUG

      printf("[strm][%p] Data received\n", Stream);
#endif
      if (client->quic_buffer_map_.find(Stream) ==
          client->quic_buffer_map_.end()) {
        client->quic_buffer_map_[Stream].reserve(256);
      }

      for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
        const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

        uint8_t *buf_ptr = buffer->Buffer;
        uint8_t *buf_end = buffer->Buffer + buffer->Length;

        if (buffer->Length > 0) {
          std::vector<uint8_t> &strm_buf = client->quic_buffer_map_[Stream];
          strm_buf.insert(strm_buf.end(), buf_ptr, buf_end);
        }
      }

      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:

      // The peer gracefully shut down its send direction of the stream.
#ifdef QUIC_DEBUG

      printf("[strm][%p] Peer aborted\n", Stream);
#endif
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      // The peer aborted its send direction of the stream.
#ifdef QUIC_DEBUG

      printf("[strm][%p] Peer shut down\n", Stream);
#endif
      if (client->quic_buffer_map_.find(Stream) ==
          client->quic_buffer_map_.end()) {
        LogError("No buffer found for Stream");
        break;
      }

      {
        std::unique_ptr<Http3FrameHandler> frame_handler =
            std::make_unique<Http3FrameHandler>(
                client->transport_, client->frame_builder_, client->codec_);

        frame_handler->ProcessFrames(Stream, client->quic_buffer_map_[Stream]);
      }

      client->quic_buffer_map_.erase(Stream);

      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.

#ifdef QUIC_DEBUG

      printf("[strm][%p] Stream is officially closed\n", Stream);
#endif
      if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
        ms_quic_->StreamClose(Stream);
      }
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

// Saves file in format: Ticket Length | Ticket
static void SaveResumptionTicketToFile(const uint8_t *resumptionTicket,
                                       uint32_t ticketLength) {
  const std::string filename = "ticket";
  std::ofstream outFile(filename, std::ios::binary);

  if (outFile.is_open()) {
    uint32_t networkOrder = htonl(ticketLength);
    outFile.write(reinterpret_cast<const char *>(&networkOrder),
                  sizeof(networkOrder));

    outFile.write(reinterpret_cast<const char *>(resumptionTicket),
                  ticketLength);
    outFile.close();
    std::cout << "Resumption ticket saved to file: " << filename << std::endl;
  } else {
    std::cout << "Failed to open file for writing: " << filename << std::endl;
  }
}

// The clients's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    QuicClient::ConnectionCallback(_In_ HQUIC Connection,
                                   _In_opt_ void *Context,
                                   _Inout_ QUIC_CONNECTION_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);

  QuicClient *client = reinterpret_cast<QuicClient *>(Context);
  if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
    const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
    if (SslKeyLogFile != NULL) {
      WriteSslKeyLogFile(SslKeyLogFile, &client->secrets_);
    }
  }

  switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
//
// The handshake has completed for the connection.
#ifdef QUIC_DEBUG

      printf("[conn][%p] Connected\n", Connection);
#endif

      QuicSend(Connection, Context);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
          QUIC_STATUS_CONNECTION_IDLE) {
        printf("[conn][%p] Successfully shut down on idle.\n", Connection);
      } else {
        printf("[conn][%p] Shut down by transport, 0x%x\n", Connection,
               Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
      }
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
#ifdef QUIC_DEBUG
      printf(
          "[conn][%p] Shut down by peer, 0x%llu\n", Connection,
          static_cast<uint64_t>(Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode));
#endif
      // The connection was explicitly shut down by the peer.
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      // The connection has completed the shutdown process and is ready to
      // be safely cleaned up.

#ifdef QUIC_DEBUG

      printf("[conn][%p] Connection officially closed\n", Connection);
#endif
      if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
        ms_quic_->ConnectionClose(Connection);
      }
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
// A resumption ticket (also called New Session Ticket or NST) was
// received from the server.
#ifdef QUIC_DEBUG
      printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection,
             Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
#endif
      {
        SaveResumptionTicketToFile(
            Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
            Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);

        // for (uint32_t i = 0;
        //      i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
        //      i++) {
        //   printf("%.2X",
        //          (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        // }
        // printf("\n");

        break;
      }

    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}
