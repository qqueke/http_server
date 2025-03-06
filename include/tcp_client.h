#ifndef TCPCLIENT_HPP
#define TCPCLIENT_HPP

#include <netinet/in.h>

#include <memory>
#include <vector>

// #include "http2_frame_handler.h"
#include "codec.h"
#include "http2_frame_builder.h"
#include "tls_manager.h"
#include "transport.h"

class TcpClient {
 public:
  TcpClient(int argc, char *argv[],
            const std::vector<std::pair<std::string, std::string>> &requests);
  ~TcpClient();

  const std::vector<std::pair<std::string, std::string>> requests_;
  void Run();

 private:
  std::unique_ptr<TlsManager> tls_manager_;

  // std::unique_ptr<Http2ClientFrameHandler> frame_handler_;

  std::shared_ptr<TcpTransport> transport_;

  std::shared_ptr<Http2FrameBuilder> frame_builder_;

  std::shared_ptr<HpackCodec> codec_;

  int socket_;
  struct addrinfo *socket_addr_;

  void SendHttp1Request(SSL *client_ssl);
  void SendHttp2Request(SSL *client_ssl);
  void RecvHttp2Response(SSL *client_ssl, std::mutex &conn_mutex);
};

#endif  // TCPCLIENT_HPP
