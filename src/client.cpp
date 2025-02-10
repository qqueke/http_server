#include <unordered_map>

#include "cCallbacks.hpp"
#include "utils.hpp"
std::unordered_map<HQUIC, std::vector<uint8_t>> BufferMap;

void RunClient(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[]) {
  // Load the client configuration based on the "unsecure" command line option.
  if (!ClientLoadConfiguration(GetFlag(argc, argv, "unsecure"))) {
    return;
  }

  QUIC_STATUS Status;
  const char *ResumptionTicketString = NULL;
  const char *SslKeyLogFile = getenv(SslKeyLogEnvVar);
  HQUIC Connection = NULL;

  int i = 0;
  // Allocate a new connection object.
  if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration,
                                                  ClientConnectionCallback, &i,
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

int QUIC_MAIN_EXPORT main(_In_ int argc,
                          _In_reads_(argc) _Null_terminated_ char *argv[]) {
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
    printf("MsQuicOpen2 failed, 0x%x!\n", Status);
    goto Error;
  }

  // Create a registration for the app's connections.
  if (QUIC_FAILED(Status =
                      MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
    printf("RegistrationOpen failed, 0x%x!\n", Status);
    goto Error;
  }

  if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
    PrintUsage();
  } else if (GetFlag(argc, argv, "client")) {
    RunClient(argc, argv);
  }
  // else if (GetFlag(argc, argv, "server")) {
  //    RunServer(argc, argv);
  // }
  else {
    PrintUsage();
  }

Error:

  if (MsQuic != NULL) {
    if (Configuration != NULL) {
      MsQuic->ConfigurationClose(Configuration);
    }
    if (Registration != NULL) {
      // This will block until all outstanding child objects have been
      // closed.
      MsQuic->RegistrationClose(Registration);
    }
    MsQuicClose(MsQuic);
  }

  return (int)Status;
}
