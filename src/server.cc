#include "server.h"

#include <fcntl.h>
#include <lshpack.h>
#include <msquic.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/poll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#include "log.h"
#include "quic_server.h"
#include "router.h"
#include "static_content_handler.h"
#include "tcp_server.h"
#include "utils.h"

// #define HTTP2_DEBUG

bool shouldShutdown(false);

HttpServer::~HttpServer() {
  std::cout << "Server shutdown gracefully" << std::endl;
}

void HttpServer::AddRoute(const std::string &method, const std::string &path,
                          const ROUTE_HANDLER &handler) {
  router_->AddRoute(method, path, handler);
}

void HttpServer::Run() {
  quic_server_->Run();
  tcp_server_->Run();
}

HttpServer::HttpServer(int argc, char *argv[]) {
  router_ = std::make_shared<Router>();
  static_content_handler_ = std::make_shared<StaticContentHandler>();
  tcp_server_ = std::make_unique<TcpServer>(router_, static_content_handler_);
  quic_server_ = std::make_unique<QuicServer>(router_, static_content_handler_,
                                              argc, argv);
};
