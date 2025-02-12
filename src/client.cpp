#include <unordered_map>

#include "cCallbacks.hpp"
#include "utils.hpp"

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
