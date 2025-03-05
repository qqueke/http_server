#ifndef TCPCLIENT_HPP
#define TCPCLIENT_HPP

#include <netinet/in.h>

#include <memory>

#include "framehandler.hpp"
#include "tlsmanager.hpp"

class TcpClient {
private:
  std::unique_ptr<TlsManager> tlsManager;

  std::unique_ptr<Http2ClientFrameHandler> frameHandler;

  std::shared_ptr<TcpTransport> transport;

  std::shared_ptr<Http2FrameBuilder> frameBuilder;

  std::shared_ptr<HpackCodec> codec;

  int tcpSocket;
  struct addrinfo *tcpSocketAddr;

  void AcceptConnections();
  void HandleRequest(int clientSocket);
  void HandleHTTP1Request(SSL *clientSSL);
  void HandleHTTP2Request(SSL *clientSSL);

public:
  TcpClient();
  ~TcpClient();

  void Run();
};

#endif // TCPCLIENT_HPP
