// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/routes.h"

#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <utility>

Routes::Routes() {}

Routes::~Routes() {}

std::pair<std::string, std::string> Routes::HelloHandler(
    const std::string &data) {
  std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 14\r\n"
      "\r\n";

  std::string body = "Hello, world!\n";

  return {headers, body};
}

std::pair<std::string, std::string> Routes::EchoHandler(
    const std::string &data) {
  std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: ";

  headers.append(std::to_string(data.size() + 1)).append("\r\n\r\n");

  std::string body = data;
  body.append("\n");

  return {headers, body};
}
