#include "client.h"

#include <poll.h>
#include <sys/poll.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>

#include "quic_client.h"
#include "utils.h"

HttpClient::HttpClient(int argc, char *argv[]) {
  std::string requestsFile;

  if ((requestsFile = GetValue2(argc, argv, "requests")) != "") {
    ParseRequestsFromFile(requestsFile);
  }

  tcp_client_ = std::make_unique<TcpClient>(argc, argv, requests);

  quic_client_ = std::make_unique<QuicClient>(argc, argv, requests);
}

HttpClient::~HttpClient() { std::cout << "Deconstructing Client" << std::endl; }

void HttpClient::Run(int argc, char *argv[]) {
  quic_client_->Run(argc, argv);

  tcp_client_->Run();
}

void HttpClient::ParseRequestsFromFile(const std::string &file_path) {
  std::ifstream file(file_path);
  std::string line;
  std::string headers{};
  std::string body{};

  if (file_path.empty()) {
    std::cerr << "Invalid file name!" << std::endl;
    return;
  }

  if (!file.is_open()) {
    std::cerr << "Failed to open file: " << file_path << std::endl;
    return;
  }

  while (std::getline(file, line)) {
    // Skip empty lines
    if (line.empty())
      continue;

    // If the line starts with "Body:", save the body and store the request
    if (line.starts_with("Body:")) {
      body = line.substr(5);

      if (body.empty()) {
        requests.emplace_back(headers, body);
        headers.clear();
        continue;
      }

      while (std::getline(file, line)) {
        if (line.empty())
          break;

        body += "\r\n" + line;
      }

      if (body[0] == ' ') {
        body.erase(0, 1);
      }

      requests.emplace_back(headers, body);
      headers.clear();
      body.clear();

    } else {
      headers += line + "\r\n";
    }
  }

  if (!headers.empty() || !body.empty()) {
    requests.emplace_back(headers, body);
  }
}
