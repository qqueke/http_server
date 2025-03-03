// #include "client.cpp"
// #include <gperftools/profiler.h>
#include <memory.h>

#include <csignal>
#include <memory>
#include <ostream>
#include <thread>

#include "client.hpp"
#include "log.hpp"
#include "routes.cpp"
#include "server.hpp"
#include "utils.hpp"

// void startProfiling() { ProfilerStart("my_profiler_output.prof"); }
//
// void stopProfiling() { ProfilerStop(); }

extern bool shouldShutdown;

// void *operator new(size_t size) {
//   std::cout << "Allocating " << size << "bytes\n";
//   return malloc(size);
// }
// void operator delete(void *memory, size_t size) {
//   std::cout << "Deallocating " << size << "bytes\n";
//   free(memory);
// }

static void signalHandler(int signal) {
  std::cout << "\nReceived signal " << signal << ". Shutting down server...\n";
  shouldShutdown = true;
}

int main(int argc, char *argv[]) {
  // startProfiling();
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
    printf("MsQuicOpen2 failed, 0x%x!\n", Status);
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

  // Create a registration for the app's connections.
  if (QUIC_FAILED(Status =
                      MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
    printf("RegistrationOpen failed, 0x%x!\n", Status);
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

  if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
    PrintUsage();
  } else if (GetFlag(argc, argv, "client")) {
    std::unique_ptr<HttpClient> client =
        std::make_unique<HttpClient>(argc, argv);

    client->Run(argc, argv);

    getchar();
  } else if (GetFlag(argc, argv, "server")) {
    signal(SIGPIPE, SIG_IGN);       // SIGPIPE
    signal(SIGINT, signalHandler);  // Ctrl+C
    signal(SIGTERM, signalHandler); // Termination signal

    {
      std::unique_ptr<HttpServer> server =
          std::make_unique<HttpServer>(argc, argv);

      // HttpServer::Initialize(argc, argv);
      // std::unique_ptr<HttpServer> server(HttpServer::GetInstance());
      // nice to have this as a function declared elsewhere
      // server->AddRoute("GET", "/hello", helloHandler);
      // server->AddRoute("GET", "/goodbye", goodbyeHandler);

      std::thread([]() { periodicFlush(); }).detach();

      std::cout << "Server started, press Ctrl+C to stop.\n";

      server->Run();
    }
    // shouldShutdown = true;
    std::cout << "Calling the shutdown flush" << std::endl;
    std::thread t([]() { shutdownFlush(); });
    t.join();

  } else {
    PrintUsage();
  }

  // stopProfiling();
  return 0;
}
