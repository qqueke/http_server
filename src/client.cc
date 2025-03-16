// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/client.h"

#include <poll.h>
#include <sys/poll.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include "../include/quic_client.h"
#include "../include/utils.h"

HttpClient::HttpClient(int argc, char *argv[]) {
  std::string requestsFile;

  if ((requestsFile = GetValue2(argc, argv, "requests")) != "") {
    ParseRequestsFromFile(requestsFile);
  }

  tcp_client_ = std::make_unique<TcpClient>(argc, argv, requests_);

  quic_client_ = std::make_unique<QuicClient>(argc, argv, requests_);

  // int n_clients = 100;
  // quic_client_vector_.reserve(n_clients);  // Optional: Reserve space for
  // for (int i = 0; i < n_clients; ++i) {
  //   quic_client_vector_.emplace_back(argc, argv, requests_);
  // }
}

HttpClient::~HttpClient() { std::cout << "Deconstructing Client" << std::endl; }

void HttpClient::Run(int argc, char *argv[]) {
  // quic_client_->Run(argc, argv);
  //
  // for (auto &quic_client : quic_client_vector_) {
  //   quic_client.Run(argc, argv);
  // }

  tcp_client_->Run();
}

void HttpClient::ParseRequestsFromFile(const std::string &file_path) {
  std::ifstream file(file_path);
  std::string line;
  std::string headers = "";
  std::string body = "";

  if (file_path.empty()) {
    std::cerr << "Invalid file name!" << std::endl;
    return;
  }

  if (!file.is_open()) {
    std::cerr << "Failed to open file: " << file_path << std::endl;
    return;
  }

  bool expect_body = false;

  while (std::getline(file, line)) {
    // Skip empty lines
    if (line.empty()) {
      expect_body = true;
      continue;
    }

    if (line.starts_with("Body:")) {
      body = line.substr(5);  //  Just the body text

      // Remove leading spaces
      while (!body.empty() && body.front() == ' ') {
        body.erase(0, 1);
      }

      // Remove trailing spaces
      while (!body.empty() && body.back() == ' ') {
        body.pop_back();
      }

      while (std::getline(file, line)) {
        if (line.empty()) break;

        // Remove leading spaces
        while (!line.empty() && line.front() == ' ') {
          line.erase(0, 1);
        }

        // Remove trailing spaces
        while (!line.empty() && line.back() == ' ') {
          line.pop_back();
        }

        if (body.empty()) {
          body = line;
        } else {
          body += "\r\n" + line;
        }
      }

      if (!headers.empty()) {
        requests_.emplace_back(headers, body);
        headers.clear();
        body.clear();
      }
    } else if (expect_body) {
      // Request with no body found
      expect_body = false;
      if (!headers.empty()) {
        requests_.emplace_back(headers, body);
        headers.clear();
        body.clear();
      }
      headers.clear();
    } else {
      headers += line + "\r\n";
    }
  }

  if (expect_body && !headers.empty()) {
    requests_.emplace_back(headers, "");
  }
}
