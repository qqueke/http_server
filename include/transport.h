// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file transport.h
 * @brief Defines transport management classes for TCP and QUIC protocols.
 *
 * This file contains the `ITransportManager` interface and the `TcpTransport`
 * and `QuicTransport` classes that handle sending and receiving data over TCP
 * and QUIC protocols. The classes implement transport-specific logic for
 * sending and receiving individual packets, batches of packets, and files.
 */

#ifndef INCLUDE_TRANSPORT_H_
#define INCLUDE_TRANSPORT_H_

#include <msquic.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include "../include/log.h"
#include "../include/utils.h"

/**
 * @interface ITransportManager
 * @brief Interface for transport managers (TCP or QUIC).
 *
 * This interface defines methods for sending data over a transport connection,
 * either TCP or QUIC. Classes implementing this interface provide the specific
 * transport protocol's logic.
 */
class ITransportManager {
 public:
  /**
   * @brief Destructor for the ITransportManager interface.
   *
   * The destructor is virtual to ensure derived classes can clean up resources
   * properly.
   */
  virtual ~ITransportManager() = default;

  /**
   * @brief Sends data over the transport connection.
   *
   * This method sends a vector of bytes over an existing transport connection.
   *
   * @param connection A pointer to the connection object.
   * @param bytes A vector of bytes to be sent.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  virtual int Send(void *connection, const std::vector<uint8_t> &bytes) = 0;

  /**
   * @brief Sends a batch of data over the transport connection.
   *
   * This method sends a vector of byte vectors (batch of packets) over an
   * existing transport connection.
   *
   * @param connection A pointer to the connection object.
   * @param bytes A vector of byte vectors to be sent in a batch.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  virtual int SendBatch(void *connection,
                        const std::vector<std::vector<uint8_t>> &bytes) = 0;
};

/**
 * @class TcpTransport
 * @brief TCP transport manager that handles sending and receiving data over TCP
 * connections.
 *
 * This class implements the `ITransportManager` interface and provides methods
 * for sending and receiving data over TCP connections. It supports both
 * individual and batched packet sends, and file sending. Additionally, it
 * handles sending data with retry logic and delays between sending and
 * receiving.
 */
class TcpTransport : public ITransportManager {
 public:
  /**
   * @brief Constructs a TCP transport manager with default settings.
   */
  TcpTransport();

  /**
   * @brief Constructs a TCP transport manager with custom settings for retries,
   * send delay, and receive delay.
   *
   * @param retry_count The number of retries to attempt when sending data.
   * @param sendDelayMS The delay in milliseconds between sending packets.
   * @param recvDelayMS The delay in milliseconds between receiving packets.
   */
  TcpTransport(uint32_t retry_count, uint32_t sendDelayMS,
               uint32_t recvDelayMS);

  /**
   * @brief Sends data over a TCP connection.
   *
   * This method sends a vector of bytes over the given TCP connection.
   *
   * @param connection A pointer to the SSL connection object.
   * @param bytes A vector of bytes to be sent.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int Send(void *connection, const std::vector<uint8_t> &bytes) override;

  /**
   * @brief Sends data over a TCP connection.
   *
   * This method sends a std::string over the given TCP connection.
   *
   * @param connection A pointer to the SSL connection object.
   * @param bytes A text string to be sent.
   * @return Returns 0 on success, or a non-zero value on failure.
   */

  int Send(void *connection, const void *data, size_t size, std::mutex &mut) {
    SSL *ssl = static_cast<SSL *>(connection);

    uint32_t retry_count = 0;
    size_t totalBytesSent = 0;
    int sentBytes = 0;
    while (totalBytesSent < size) {
      {
        std::lock_guard<std::mutex> lock(mut);
        sentBytes =
            SSL_write(ssl, static_cast<const uint8_t *>(data) + totalBytesSent,
                      static_cast<int>(size - totalBytesSent));
      }

      if (sentBytes > 0) {
        totalBytesSent += sentBytes;
      } else {
        int error = SSL_get_error(ssl, sentBytes);
        if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
          if (retry_count < _retry_count_) {
            ++retry_count;
            std::this_thread::sleep_for(
                std::chrono::milliseconds(_sendDelayMS_));
            continue;
          } else {
            LogError("Max retries reached while trying to send data");
            return ERROR;
          }
        } else {
          LogError(GetSSLErrorMessage(error));
          return ERROR;
        }
      }
    }

    return 0;
  }

  int Send(void *connection, const void *data, size_t size) {
    SSL *ssl = static_cast<SSL *>(connection);

    uint32_t retry_count = 0;
    size_t totalBytesSent = 0;

    while (totalBytesSent < size) {
      int sentBytes =
          SSL_write(ssl, static_cast<const uint8_t *>(data) + totalBytesSent,
                    static_cast<int>(size - totalBytesSent));

      if (sentBytes > 0) {
        totalBytesSent += sentBytes;
      } else {
        int error = SSL_get_error(ssl, sentBytes);
        if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
          if (retry_count < _retry_count_) {
            ++retry_count;
            std::this_thread::sleep_for(
                std::chrono::milliseconds(_sendDelayMS_));
            continue;
          } else {
            LogError("Max retries reached while trying to send data");
            return ERROR;
          }
        } else {
          LogError(GetSSLErrorMessage(error));
          return ERROR;
        }
      }
    }

    return 0;
  }

  /**
   * @brief Sends data over a TCP connection with additional mutex locking.
   *
   * This method sends a vector of bytes over the given TCP connection while
   * ensuring thread safety by using a mutex.
   *
   * @param connection A pointer to the SSL connection object.
   * @param bytes A vector of bytes to be sent.
   * @param mut A mutex used for thread synchronization during the send
   * operation.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int Send(void *connection, const std::vector<uint8_t> &bytes,
           std::mutex &mut);

  /**
   * @brief Sends a batch of data over a TCP connection.
   *
   * This method sends a vector of byte vectors (batch of packets) over a given
   * TCP connection.
   *
   * @param connection A pointer to the SSL connection object.
   * @param bytes A vector of byte vectors to be sent in a batch.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes) override;

  /**
   * @brief Sends a batch of data over a TCP connection with additional mutex
   * locking.
   *
   * This method sends a vector of byte vectors (batch of packets) over a given
   * TCP connection while ensuring thread safety using a mutex.
   *
   * @param connection A pointer to the SSL connection object.
   * @param bytes A vector of byte vectors to be sent in a batch.
   * @param mut A mutex used for thread synchronization during the send
   * operation.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes,
                std::mutex &mut);

  /**
   * @brief Reads data from a TCP connection.
   *
   * This method reads data from the specified TCP connection into the provided
   * buffer.
   *
   * @param connection A pointer to the SSL connection object.
   * @param buffer A vector to store the received data.
   * @param write_offset The offset in the buffer where to start writing data.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int Recv(void *connection, std::vector<uint8_t> &buffer,
           uint32_t write_offset);

  /**
   * @brief Reads data from a TCP connection with additional mutex locking.
   *
   * This method reads data from the specified TCP connection into the provided
   * buffer while ensuring thread safety using a mutex.
   *
   * @param connection A pointer to the SSL connection object.
   * @param buffer A vector to store the received data.
   * @param write_offset The offset in the buffer where to start writing data.
   * @param mut A mutex used for thread synchronization during the read
   * operation.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int Recv(void *connection, std::vector<uint8_t> &buffer,
           uint32_t write_offset, std::mutex &mut);

  /**
   * @brief Sends a file over a TCP connection.
   *
   * This method sends the contents of a file over a given TCP connection.
   *
   * @param connection A pointer to the SSL connection object.
   * @param fd The file descriptor of the file to be sent.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int SendFile(void *connection, int fd);

 private:
  /**
   * @brief The number of retry attempts for sending data.
   */
  uint32_t _retry_count_;

  /**
   * @brief The delay in milliseconds between sending packets.
   */
  uint32_t _sendDelayMS_;

  /**
   * @brief The delay in milliseconds between receiving packets.
   */
  uint32_t _recvDelayMS_;
};

/**
 * @class QuicTransport
 * @brief QUIC transport manager that handles sending and receiving data over
 * QUIC connections.
 *
 * This class implements the `ITransportManager` interface and provides methods
 * for sending and receiving data over QUIC connections. It supports sending
 * both individual and batched packets.
 */
class QuicTransport : public ITransportManager {
 public:
  /**
   * @brief Constructs a QUIC transport manager with default settings.
   */
  QuicTransport() = default;

  /**
   * @brief Constructs a QUIC transport manager with a specified QUIC API table.
   *
   * @param ms_quic A pointer to the QUIC API table used to interact with QUIC.
   */
  explicit QuicTransport(const QUIC_API_TABLE *ms_quic) : ms_quic_(ms_quic) {}

  /**
   * @brief Sends data over a QUIC connection.
   *
   * This method sends a vector of bytes over the given QUIC connection.
   *
   * @param connection A pointer to the QUIC stream handle.
   * @param bytes A vector of bytes to be sent.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int Send(void *connection, const std::vector<uint8_t> &bytes) override;

  /**
   * @brief Sends data over a QUIC connection with specified send flags.
   *
   * This method sends a vector of bytes over a QUIC connection with specified
   * send flags.
   *
   * @param connection A pointer to the QUIC stream handle.
   * @param bytes A vector of bytes to be sent.
   * @param flag The send flags to use for the QUIC send operation.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int Send(void *connection, const std::vector<uint8_t> &bytes,
           enum QUIC_SEND_FLAGS flag);

  /**
   * @brief Sends a batch of data over a QUIC connection.
   *
   * This method sends a vector of byte vectors (batch of packets) over a given
   * QUIC connection.
   *
   * @param connection A pointer to the QUIC stream handle.
   * @param bytes A vector of byte vectors to be sent in a batch.
   * @return Returns 0 on success, or a non-zero value on failure.
   */
  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes) override;

 private:
  /**
   * @brief The QUIC API table used for QUIC operations.
   */
  const QUIC_API_TABLE *ms_quic_;
};

#endif  // INCLUDE_TRANSPORT_H_
