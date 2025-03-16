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

#include <cstddef>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

bool Routes::static_init_ = false;

std::weak_ptr<Database> Routes::db_;

Routes::Routes(const std::shared_ptr<Database> &db) {
  if (!static_init_) {
    InitializeSharedResources(db);
  }
}

Routes::~Routes() { static_init_ = false; };

void Routes::InitializeSharedResources(const std::shared_ptr<Database> &db) {
  db_ = db;
  static_init_ = true;
}

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

std::pair<std::string, std::string> Routes::AddUser(const std::string &data) {
  std::string_view data_view = data;

  std::string username;
  std::string customer_name;
  size_t pos = data_view.find(',');
  if (pos != std::string::npos) {
    username = data_view.substr(0, pos);
    customer_name = data_view.substr(pos + 1, data.size() - pos + 1);
    // std::cout << "Data parsing: username: " << username
    //           << " and custoemr_name: " << customer_name << std::endl;

    while (!username.empty() && username.front() == ' ') {
      username.erase(0, 1);
    }

    // Remove trailing spaces
    while (!username.empty() && username.back() == ' ') {
      username.pop_back();
    }

    while (!customer_name.empty() && customer_name.front() == ' ') {
      customer_name.erase(0, 1);
    }

    // Remove trailing spaces
    while (!customer_name.empty() && customer_name.back() == ' ') {
      customer_name.pop_back();
    }
  }

  std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: ";

  std::string body;

  if (db_.lock()->RegisterCustomer(Customer(username, customer_name)) == -1) {
    body = "Unable to create user: " + data;
  } else {
    body = "Created user: " + data;
  }

  body.append("\n");

  headers.append(std::to_string(body.size())).append("\r\n\r\n");

  return {headers, body};
}

std::pair<std::string, std::string> Routes::DeleteUser(
    const std::string &data) {
  int ret = db_.lock()->DeleteCustomer(data);

  std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: ";

  if (ret == 0) {
    std::string body = "Deleted user with username: " + data;
    body.append("\n");

    headers.append(std::to_string(body.size())).append("\r\n\r\n");
    return {headers, body};
  } else {
    std::string body = "Could not delete user with username: " + data;
    body.append("\n");

    headers.append(std::to_string(body.size())).append("\r\n\r\n");
    return {headers, body};
  }
}

std::pair<std::string, std::string> Routes::SearchUser(
    const std::string &data) {
  auto entry = db_.lock()->Search4Customer(data);
  std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: ";

  if (entry) {
    std::string body = "Found user: " + entry->customer_name;
    body.append("\n");

    headers.append(std::to_string(body.size())).append("\r\n\r\n");

    return {headers, body};
  } else {
    std::string body = "Could not find user";
    body.append("\n");

    headers.append(std::to_string(body.size())).append("\r\n\r\n");

    return {headers, body};
  }
}
