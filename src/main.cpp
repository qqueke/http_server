#include "log.hpp"
#include "routes.cpp"
#include "server.hpp"
#include <csignal>
#include <memory.h>
#include <memory>
#include <thread>

extern std::atomic<bool> shouldShutdown;

// void *operator new(size_t size) {
//   std::cout << "Allocating " << size << "bytes\n";
//   return malloc(size);
// }
//
// void operator delete(void *memory, size_t size) {
//   std::cout << "Deallocating " << size << "bytes\n";
//   free(memory);
// }

static void signalHandler(int signal) {
  std::cout << "\nReceived signal " << signal << ". Shutting down server...\n";
  shouldShutdown = true;
}

int main() {
  signal(SIGINT, signalHandler);  // Ctrl+C
  signal(SIGTERM, signalHandler); // Termination signal

  {
    std::unique_ptr<HTTPServer> server = std::make_unique<HTTPServer>();

    // nice to have this as a function declared elsewhere
    server->addRoute("GET", "/hello", helloHandler);
    server->addRoute("GET", "/goodbye", goodbyeHandler);

    std::thread([]() { periodicFlush(); }).detach();

    std::cout << "Server started, press Ctrl+C to stop.\n";

    server->run();
  }

  std::cout << "Calling the shutdown flush" << std::endl;
  std::thread t([]() { shutdownFlush(); });
  t.join();

  return 0;
}
