#ifndef TCPSERVER_HPP
#define TCPSERVER_HPP

#include <netinet/in.h>

#include <memory>

#include "http2_frame_handler.h"
#include "router.h"
#include "tls_manager.h"

class TcpServer {
 public:
  explicit TcpServer(const std::shared_ptr<Router> &router);
  ~TcpServer();

  void Run();

 private:
  std::unique_ptr<TlsManager> tls_manager_;

  std::unique_ptr<Http2ServerFrameHandler> frame_handler_;

  std::shared_ptr<TcpTransport> transport_;

  std::shared_ptr<Http2FrameBuilder> frame_builder_;

  std::shared_ptr<HpackCodec> codec_;

  std::weak_ptr<Router> router_;

  int socket_;
  struct addrinfo *socket_addr_;

  void AcceptConnections();
  void HandleRequest(int client_socket);
  void HandleHTTP1Request(SSL *client_ssl);
  void HandleHTTP2Request(SSL *client_ssl);
};

#endif  // TCPSERVER_HPP
