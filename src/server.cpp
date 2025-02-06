#include "server.hpp"
#include "/home/QQueke/Documents/Repositories/msquic/src/inc/msquic.h"
#include "log.hpp"
#include "router.hpp"
#include "sCallbacks.hpp"
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
// #include <msquic.h>
#include "utils.hpp"
#include <mutex>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>


std::atomic<bool> shouldShutdown(false);

std::string HTTPServer::threadSafeStrerror(int errnum) {
  std::lock_guard<std::mutex> lock(strerrorMutex);
  return {strerror(errnum)};
}

int HTTPServer::validateRequest(const std::string &request, std::string &method,
                                std::string &path, SSL *clientSock,
                                bool &acceptEncoding) {

  std::istringstream requestStream(request);
  std::string line;

  std::getline(requestStream, line);
  std::istringstream requestLine(line);
  std::string protocol;
  requestLine >> method >> path >> protocol;

  if (method != "GET" && method != "POST" && method != "PUT") {
    router->routeRequest("NA", "", clientSock);
    return ERROR;
  }

  if (path.empty() || path[0] != '/' || path.find("../") != std::string::npos) {
    router->routeRequest("BR", "", clientSock);
    return ERROR;
  }

  if (protocol != "HTTP/1.1" && protocol != "HTTP/2") {
    router->routeRequest("UP", "", clientSock);
    return ERROR;
  }

  // header, value
  std::unordered_map<std::string, std::string> headers;
  while (std::getline(requestStream, line) && !line.empty()) {

    if (line.size() == 1) {
      continue;
    }

    auto colonPos = line.find(": ");
    if (colonPos == std::string::npos) {
      std::cout << "WhatThisIs\n";
      router->routeRequest("BR", "", clientSock);
      return ERROR;
    }

    std::string key = line.substr(0, colonPos);
    std::string value = line.substr(colonPos + 2);

    headers[key] = value;
  }

  // Validate Headers

  // If we don't  find  host then it is a bad request
  if (headers.find("Host") == headers.end()) {
    router->routeRequest("BR", "", clientSock);
    return ERROR;
  }

  // If is a POST and has  no content length it is a bad request
  if (method == "POST" && headers.find("Content-Length") == headers.end()) {
    router->routeRequest("LR", "", clientSock);
    return ERROR;
  }

  // Parse Body (if has content-length)
  std::string body;
  if (headers.find("Content-Length") != headers.end()) {
    size_t contentLength = std::stoi(headers["Content-Length"]);

    body.resize(contentLength);
    requestStream.read(body.data(), (long)contentLength);

    // If body size  doesnt match the content length defined then bad request
    if (body.size() != contentLength) {
      router->routeRequest("BR", "", clientSock);
      return ERROR;
    }
  }

  // Not even bothering with enconding type
  if (headers.find("Accept-Encoding") != headers.end()) {
    acceptEncoding = true;
  }

  // If all validations pass
  std::cout << "Request successfully validated!\n";

  return 0;
}

void HTTPServer::clientHandlerThread(
    int clientSock, std::chrono::high_resolution_clock::time_point startTime) {

  std::array<char, BUFFER_SIZE> buffer{};
  std::string request;

  // Create SSL object
  SSL *ssl = SSL_new(ctx);

  //  sets the file descriptor clientSock as the input/output facility for the
  //  TLS/SSL
  SSL_set_fd(ssl, clientSock);

  // TLS/SSL handshake
  if (SSL_accept(ssl) <= 0) {
    LogError("SSL handshake failed");
    SSL_free(ssl);
    close(clientSock);
    return;
  }

  if (activeConnections >= MAX_CONNECTIONS) {
    router->routeRequest("CL", "", ssl);
    LogError("Connections limit exceeded");
    SSL_free(ssl);
    close(clientSock);
    return;
  }

  activeConnections++;

  std::string method{};
  std::string path{};
  std::string status{};

  // Just to not delete the while loop
  bool keepAlive = true;

  while (!shouldShutdown && keepAlive) {
    keepAlive = false;

    ssize_t bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);

    if (bytesReceived == 0) {
      LogError("Client closed the connection");
      break;
    } else if (bytesReceived < 0) {
      LogError("Failed to receive data");
      break;
    }

    request.append(buffer.data(), bytesReceived);

    while (bytesReceived == BUFFER_SIZE && !shouldShutdown) {
      // struct pollfd pollFds(clientSock, POLLIN, 0);
      //
      // int polling = poll(&pollFds, 1, 0.5 * 1000);
      // if (polling == 0) {
      //   LogError("No more data to read");
      //   break;
      // } else if (polling == -1) {
      //   LogError("Poll error, attempting to recv data");
      // }

      if (SSL_pending(ssl) == 0) {
        LogError("No more data to read");
        break;
      }

      bytesReceived = SSL_read(ssl, buffer.data(), BUFFER_SIZE);
      request.append(buffer.data(), bytesReceived);
    }

    std::cout << "Raw request: " << request << std::endl;
    bool acceptEncoding = false;
    if (validateRequest(request, method, path, ssl, acceptEncoding) == ERROR) {
      LogError("Request validation was unsuccessful");
      continue;
    }

    if (path.starts_with("/static/")) {
      std::string filePath = "static" + path.substr(7);
      // Check how to proceed in here
      router->staticFileHandler(ssl, filePath, acceptEncoding);
      continue;
    }

    status = router->routeRequest(method, path, ssl);
  }

  // Timer should end  here and log it to the file

  auto endTime = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> elapsed = endTime - startTime;

  // std::cout << "Request handled in " << elapsed.count() << " seconds\n";
  std::ostringstream logStream;
  logStream << "Method: " << method << " Path: " << path
            << " Status: " << status << " Elapsed time: " << elapsed.count()
            << " s";

  LogRequest(logStream.str());

  SSL_shutdown(ssl);
  SSL_free(ssl);
  activeConnections--;
  close(clientSock);
}

HTTPServer::~HTTPServer() {
  if (serverSock != -1) {
    close(serverSock);
  }
  LogError("Server shutdown.");
  std::cout << "Server shutdown gracefully" << std::endl;
}

void HTTPServer::addRoute(
    const std::string &method, const std::string &path,
    const std::function<std::string(SSL *, const std::string)> &handler) {
  router->addRoute(method, path, handler);
}

void HTTPServer::run() {

  // Starts listening for incoming connections.
  if (QUIC_FAILED(Status =
                      MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
    printf("ListenerStart failed, 0x%x!\n", Status);
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }

  // Continue listening for connections until the Enter key is pressed.
  printf("Press Enter to exit.\n\n");
  getchar();
}

void  HTTPServer::PrintFromServer() { std::cout << "Hello from server\n"; }

HTTPServer::HTTPServer(int argc, char *argv[])
    : Status(0), activeConnections(0), Listener(nullptr) {

  // Configures the address used for the listener to listen on all IP
  // addresses and the given UDP port.
  Address = {0};
  QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&Address, UDP_PORT);

  // Load the server configuration based on the command line.
  if (!ServerLoadConfiguration(argc, argv)) {
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }

  // Create/allocate a new listener object.
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(
                      Registration, ServerListenerCallback, this, &Listener))) {
    printf("ListenerOpen failed, 0x%x!\n", Status);
    LogError("Server failed to load configuration.");
    if (Listener != NULL) {
      MsQuic->ListenerClose(Listener);
    }
    return;
  }

  router = std::make_unique<Router>();
};

// if (setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
//                sizeof timeout) == -1) {
//   LogError(threadSafeStrerror(errno));
// }
//
// if (setsockopt(clientSock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
//                sizeof timeout) == -1) {
//   LogError(threadSafeStrerror(errno));
// }

// std::thread([this, clientSock, startTime]() {
//   clientHandlerThread(clientSock, startTime);
// }).detach();
