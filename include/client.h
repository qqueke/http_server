#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cstddef>
#include <unordered_map>

#include "common.h"
#include "quic_client.h"
#include "tcp_client.h"
#include "utils.h"

class HttpClient : public HttpCore {
public:
  HttpClient(int argc, char *argv[]);
  ~HttpClient();

  // Headers, Body
  std::vector<std::pair<std::string, std::string>> requests;

  void Run(int argc, char *argv[]);

private:
  std::unique_ptr<QuicClient> quic_client_;
  std::unique_ptr<TcpClient> tcp_client_;

  void ParseRequestsFromFile(const std::string &file_path);
};

#endif
