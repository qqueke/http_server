// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include <memory.h>

#include <csignal>
#include <cstdint>
#include <iostream>
#include <memory>
#include <ostream>
#include <thread>

#include "../include/client.h"
#include "../include/log.h"
#include "../include/routes.h"
#include "../include/server.h"
#include "../include/utils.h"
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
  if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
    PrintUsage();
  } else if (GetFlag(argc, argv, "client")) {
    Logger::GetInstance("client.log");
    std::unique_ptr<HttpClient> client =
        std::make_unique<HttpClient>(argc, argv);

    auto startTime = std::chrono::high_resolution_clock::now();

    client->Run(argc, argv);

    getchar();

    auto endTime = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> elapsed = endTime - startTime;

    std::cout << "Elapsed time: " << elapsed.count() << " s\n";

  } else if (GetFlag(argc, argv, "server")) {
    Logger::GetInstance("server.log");
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    {
      // LOG("LOGGING LIKE A VILLAIN");
      // LOG_REQUEST("REQUEST LOGGING LIKE A CHIMP");

      std::shared_ptr<HttpServer> server =
          std::make_shared<HttpServer>(argc, argv);

      server->AddStringHeaderRoute("GET", "/hello",
                                   server->router_->routes_->HelloHandler);
      server->AddStringHeaderRoute("POST", "/echo",
                                   server->router_->routes_->EchoHandler);

      std::thread([]() { SetPeriodicFlush(); }).detach();
      std::cout << "Server started, press Ctrl+C to stop.\n";

      server->Run();
    }
    // shouldShutdown = true;
    std::cout << "Calling the shutdown flush" << std::endl;
    std::thread t([]() { ShutdownFlush(); });
    t.join();

  } else {
    PrintUsage();
  }

  // stopProfiling();
  return 0;
}
