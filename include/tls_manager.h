/**
 * @file tls_manager.h
 * @brief Defines the `TlsManager` class responsible for managing TLS (Transport
 * Layer Security) connections.
 *
 * This file contains the `TlsManager` class, which handles the setup,
 * configuration, and management of TLS connections for both client and server
 * sides. It includes methods for loading certificates, performing the
 * handshake, and handling ALPN (Application-Layer Protocol Negotiation).
 */

#ifndef TLS_MANAGER_H
#define TLS_MANAGER_H

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <string>

/**
 * @enum TlsMode
 * @brief Enum to specify the mode of operation for TLS (either SERVER or
 * CLIENT).
 *
 * This enum defines whether the `TlsManager` will be configured for a server or
 * a client role.
 */
enum TlsMode : uint8_t { SERVER, CLIENT };

/**
 * @class TlsManager
 * @brief Manages TLS connections and provides utility functions for certificate
 * handling, SSL context creation, and handshakes.
 *
 * The `TlsManager` class abstracts the process of establishing a secure TLS
 * connection. It provides methods for loading certificates, creating SSL
 * objects, performing handshakes, and retrieving protocol information. It
 * supports both client and server modes of operation.
 */
class TlsManager {
public:
  /**
   * @brief Constructs a `TlsManager` for a specified mode (SERVER or CLIENT).
   *
   * This constructor initializes the TLS manager in either server or client
   * mode.
   *
   * @param mode The TLS mode (either SERVER or CLIENT).
   */
  TlsManager(TlsMode mode);

  /**
   * @brief Constructs a `TlsManager` with a specified retry count for TLS
   * handshakes.
   *
   * This constructor initializes the TLS manager in either server or client
   * mode, and sets the retry count for performing handshakes.
   *
   * @param mode The TLS mode (either SERVER or CLIENT).
   * @param retry_count The number of retries to attempt during the TLS
   * handshake.
   */
  TlsManager(TlsMode mode, uint32_t retry_count);

  /**
   * @brief Destructor for the `TlsManager` class.
   *
   * The destructor cleans up any resources used by the TLS manager, including
   * the SSL context.
   */
  ~TlsManager();

  /**
   * @brief Loads the certificate and key files for TLS communication.
   *
   * This method loads the specified certificate and private key files into the
   * SSL context. These files are necessary for encrypting and decrypting data
   * during the TLS connection.
   *
   * @param certPath The path to the certificate file.
   * @param keyPath The path to the private key file.
   * @return Returns 0 if successful, or a non-zero value on failure.
   */
  int LoadCertificates(const std::string &cert_path,
                       const std::string &key_path);

  /**
   * @brief Creates an SSL object for a given socket.
   *
   * This method creates a new SSL object associated with the provided socket,
   * which will be used for TLS communication.
   *
   * @param socket The socket descriptor to associate with the SSL object.
   * @return A pointer to the created SSL object.
   */
  SSL *CreateSSL(int socket);

  /**
   * @brief Deletes an SSL object.
   *
   * This method cleans up and frees the resources associated with the provided
   * SSL object.
   *
   * @param ssl The SSL object to be deleted.
   */
  void DeleteSSL(SSL *ssl);

  /**
   * @brief Performs the TLS handshake with the given socket.
   *
   * This method initiates the TLS handshake process. In server mode, it listens
   * for a handshake request from the client, while in client mode, it initiates
   * the handshake with the server.
   *
   * @param ssl The SSL object associated with the connection.
   * @param socket The socket descriptor used for the handshake.
   * @return Returns 0 if the handshake is successful, or a non-zero value on
   * failure.
   */
  int Handshake(SSL *ssl, int socket);

  /**
   * @brief Retrieves the selected protocol after a successful ALPN negotiation.
   *
   * After the TLS handshake, this method retrieves the protocol negotiated
   * using ALPN.
   *
   * @param ssl The SSL object used for the TLS connection.
   * @return A string view containing the negotiated protocol.
   */
  std::string_view GetSelectedProtocol(SSL *ssl);

  /**
   * @brief Retrieves the SSL context.
   *
   * This method returns the SSL context used by the `TlsManager`. The context
   * holds the configuration settings for the SSL/TLS operations.
   *
   * @return A pointer to the SSL context.
   */
  SSL_CTX *GetContext() const { return _ctx_; }

private:
  /**
   * @brief The SSL context used for managing SSL objects.
   */
  SSL_CTX *_ctx_;

  /**
   * @brief The mode of operation for the TLS manager (either SERVER or CLIENT).
   */
  TlsMode _mode_;

  /**
   * @brief The number of handshake retries.
   */
  uint32_t _retry_count_;

  /**
   * @brief The Application-Layer Protocol Negotiation (ALPN) protocol
   * identifiers for HTTP/2.
   *
   * This static array holds the identifiers for the HTTP/2 protocol, which are
   * used in the ALPN handshake.
   */
  static constexpr std::array<unsigned char, 12> AlpnProtos = {
      2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

  /**
   * @brief Callback function for ALPN negotiation.
   *
   * This function is called during the TLS handshake to negotiate the
   * application protocol (such as HTTP/2) using ALPN.
   *
   * @param ssl The SSL object used for the handshake.
   * @param out The negotiated protocol identifier.
   * @param outlen The length of the negotiated protocol identifier.
   * @param in The available protocols.
   * @param inlen The length of the available protocols.
   * @param arg Additional argument passed to the callback.
   * @return A value indicating the success or failure of the negotiation.
   */
  static int AlpnCallback(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg);
};

#endif // TLS_MANAGER_H
