
#ifndef TLSMANAGER_HPP
#define TLSMANAGER_HPP

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <string>

enum TlsMode : uint8_t { SERVER, CLIENT };

class TlsManager {
private:
  SSL_CTX *_ctx;
  TlsMode _mode;
  uint32_t _retryCount;

  static constexpr std::array<unsigned char, 12> AlpnProtos = {
      2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

  static int AlpnCallback(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg);

public:
  TlsManager(TlsMode mode);
  TlsManager(TlsMode mode, uint32_t retryCount);
  ~TlsManager();

  int LoadCertificates(const std::string &certPath, const std::string &keyPath);

  SSL *CreateSSL(int socket);

  void DeleteSSL(SSL *ssl);

  int Handshake(SSL *ssl, int socket);

  std::string_view GetSelectedProtocol(SSL *ssl);

  SSL_CTX *GetContext() const { return _ctx; }
};

#endif // TLSMANAGER_HPP
