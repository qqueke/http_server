// #include "client.cc"
// #include <gperftools/profiler.h>
#include <memory.h>

#include <csignal>
#include <memory>
#include <ostream>
#include <thread>

#include "client.h"
#include "log.h"
#include "routes.cc"
#include "server.h"
#include "utils.h"

// void startProfiling() { ProfilerStart("my_profiler_output.prof"); }
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
      std::shared_ptr<HttpServer> server =
          std::make_shared<HttpServer>(argc, argv);

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
