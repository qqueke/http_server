
#include "tlsmanager.hpp"

#include <poll.h>
#include <sys/poll.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

#include "log.hpp"
#include "utils.hpp"

int TlsManager::AlpnCallback(SSL *ssl, const unsigned char **out,
                             unsigned char *outlen, const unsigned char *in,
                             unsigned int inlen, void *arg) {
  if (SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
                            AlpnProtos.data(),
                            AlpnProtos.size()) == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }

  return SSL_TLSEXT_ERR_NOACK;
}

TlsManager::TlsManager(TlsMode mode) : _mode(mode), _retryCount(MAX_RETRIES) {
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

  if (mode == TlsMode::SERVER) {
    _ctx = SSL_CTX_new(SSLv23_server_method());
  } else {
    _ctx = SSL_CTX_new(SSLv23_client_method());
  }

  if (!_ctx) {
    std::cerr << "Failed to create SSL context" << std::endl;
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (mode == TlsMode::SERVER) {
    SSL_CTX_set_alpn_select_cb(_ctx, AlpnCallback, NULL);
  } else {
    if (SSL_CTX_set_alpn_protos(_ctx, AlpnProtos.data(), AlpnProtos.size()) !=
        0) {
      std::cerr << "Failed to set ALPN protocols\n";
      exit(EXIT_FAILURE);
    }
  }
}

TlsManager::TlsManager(TlsMode mode, uint32_t retryCount)
    : _mode(mode), _retryCount(retryCount) {
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

  if (mode == TlsMode::SERVER) {
    _ctx = SSL_CTX_new(SSLv23_server_method());
  } else {
    _ctx = SSL_CTX_new(SSLv23_client_method());
  }

  if (!_ctx) {
    std::cerr << "Failed to create SSL context" << std::endl;
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (mode == TlsMode::SERVER) {
    SSL_CTX_set_alpn_select_cb(_ctx, AlpnCallback, NULL);
  } else {
    if (SSL_CTX_set_alpn_protos(_ctx, AlpnProtos.data(), AlpnProtos.size()) !=
        0) {
      std::cerr << "Failed to set ALPN protocols\n";
      exit(EXIT_FAILURE);
    }
  }
}

TlsManager::~TlsManager() {
  if (_ctx) {
    SSL_CTX_free(_ctx);
  }
  OPENSSL_cleanup();
}

int TlsManager::LoadCertificates(const std::string &certPath,
                                 const std::string &keyPath) {
  int ret =
      SSL_CTX_use_certificate_file(_ctx, certPath.c_str(), SSL_FILETYPE_PEM);
  if (ret <= 0) {
    LogError("Failed to load server certificate");
    return ERROR;
  }

  ret = SSL_CTX_use_PrivateKey_file(_ctx, keyPath.c_str(), SSL_FILETYPE_PEM);
  if (ret <= 0) {
    LogError("Failed to load server private key");
    return ERROR;
  }

  ret = SSL_CTX_check_private_key(_ctx);

  if (ret != 1) {
    LogError("Private key does not match the certificate!");
    return ERROR;
  }

  return 0;
}

SSL *TlsManager::CreateSSL(int socket) {
  SSL *ssl = SSL_new(_ctx);
  if (ssl == nullptr) {
    LogError("Failed to create SSL object");
    return nullptr;
  }
  int ret = SSL_set_fd(ssl, socket);
  if (ret == 0) {
    LogError("Failed to set SSL fd");
    return nullptr;
  }

  return ssl;
}

void TlsManager::DeleteSSL(SSL *ssl) { SSL_free(ssl); }

int TlsManager::Handshake(SSL *ssl, int socket) {
  int ret = 0;
  uint32_t retryCount = 0;
  struct pollfd pfd{};
  pfd.fd = socket;
  pfd.events = POLLIN | POLLOUT | POLLHUP;

  while (retryCount < _retryCount) {
    if (_mode == TlsMode::SERVER) {
      ret = SSL_accept(ssl);
    } else {
      ret = SSL_connect(ssl);
    }

    if (ret > 0) {
      return 0;
    }

    int error = SSL_get_error(ssl, ret);
    if (error == SSL_ERROR_WANT_READ) {
      poll(&pfd, 1, 1000);
      ++retryCount;
      continue;
    } else if (error == SSL_ERROR_WANT_WRITE) {
      poll(&pfd, 1, 1000);
      ++retryCount;
      continue;
    } else {
      LogError(GetSSLErrorMessage(error));
      DeleteSSL(ssl);
      return ERROR;
    }
  }
  return ERROR;
}

std::string_view TlsManager::GetSelectedProtocol(SSL *ssl) {
  const unsigned char *protocol = nullptr;
  unsigned int len = 0;

  SSL_get0_alpn_selected(ssl, &protocol, &len);
  return {reinterpret_cast<const char *>(protocol), len};
}
