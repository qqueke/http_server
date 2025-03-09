#ifndef TCPSERVER_HPP
#define TCPSERVER_HPP

#include <netinet/in.h>

#include <memory>

#include "codec.h"
#include "http2_frame_builder.h"
#include "router.h"
#include "static_content_handler.h"
#include "tls_manager.h"
#include "transport.h"

class TcpServer {
 public:
  explicit TcpServer(
      const std::shared_ptr<Router> &router,
      const std::shared_ptr<StaticContentHandler> &content_handler);
  ~TcpServer();

  void Run();

 private:
  std::unique_ptr<TlsManager> tls_manager_;

  std::shared_ptr<TcpTransport> transport_;

  std::shared_ptr<Http2FrameBuilder> frame_builder_;

  std::shared_ptr<HpackCodec> codec_;

  std::weak_ptr<Router> router_;

  std::weak_ptr<StaticContentHandler> static_content_handler_;

  int socket_;
  struct addrinfo *socket_addr_;

  void AcceptConnections();
  void HandleRequest(int client_socket);
  void HandleHTTP1Request(SSL *client_ssl);
  void HandleHTTP2Request(SSL *client_ssl);
};

#endif  // TCPSERVER_HPP
