#ifndef TCPSERVER_HPP
#define TCPSERVER_HPP

#include <netinet/in.h>

#include <memory>

#include "framehandler.hpp"
#include "router.hpp"
#include "tlsmanager.hpp"

class TcpServer {
private:
  std::unique_ptr<TlsManager> tlsManager;

  std::unique_ptr<Http2ServerFrameHandler> frameHandler;

  std::shared_ptr<TcpTransport> transport;

  std::shared_ptr<Http2FrameBuilder> frameBuilder;

  std::shared_ptr<HpackCodec> codec;

  std::weak_ptr<Router> router;

  int tcpSocket;
  struct addrinfo *tcpSocketAddr;

  void AcceptConnections();
  void HandleRequest(int clientSocket);
  void HandleHTTP1Request(SSL *clientSSL);
  void HandleHTTP2Request(SSL *clientSSL);

public:
  explicit TcpServer(const std::shared_ptr<Router> &router);
  ~TcpServer();

  void Run();
};

#endif // TCPSERVER_HPP
