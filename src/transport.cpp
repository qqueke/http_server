#include "transport.hpp"

#include <cstdint>
#include <sstream>
#include <thread>

#include "crypto.h"
#include "log.hpp"
#include "ssl.h"
#include "utils.hpp"

TcpTransport::TcpTransport()
    : _retryCount(MAX_RETRIES), _sendDelayMS(SEND_DELAY_MS),
      _recvDelayMS(RECV_DELAY_MS) {}

TcpTransport::TcpTransport(uint32_t retryCount, uint32_t sendDelayMS,
                           uint32_t recvDelayMS)
    : _retryCount(retryCount), _sendDelayMS(sendDelayMS),
      _recvDelayMS(recvDelayMS) {}

int TcpTransport::SendBatch(void *connection,
                            const std::vector<std::vector<uint8_t>> &bytes) {
  for (const auto &chunk : bytes) {
    if (Send(connection, chunk) == ERROR) {
      return ERROR;
    }
  }

  return 0;

  // SSL *ssl = static_cast<SSL *>(connection);
  // for (const auto &chunk : bytes) {
  //   uint32_t retryCount = 0;
  //   size_t totalBytesSent = 0;
  //   size_t arraySize = chunk.size();
  //
  //   while (totalBytesSent < arraySize) {
  //     int sentBytes = SSL_write(ssl, chunk.data() + totalBytesSent,
  //                               (int)(arraySize - totalBytesSent));
  //
  //     if (sentBytes > 0) {
  //       totalBytesSent += sentBytes;
  //     } else {
  //       int error = SSL_get_error(ssl, sentBytes);
  //       if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
  //         if (retryCount < _retryCount) {
  //           ++retryCount;
  //           std::this_thread::sleep_for(
  //               std::chrono::milliseconds(_sendDelayMS));
  //           continue;
  //         } else {
  //           LogError("Max retries reached while trying to send data");
  //           break;
  //         }
  //         continue;
  //       } else {
  //         LogError(GetSSLErrorMessage(error));
  //         return ERROR;
  //       }
  //     }
  //   }
  // }
  // return 0;
}

int TcpTransport::Send(void *connection, const std::vector<uint8_t> &bytes) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retryCount = 0;
  size_t totalBytesSent = 0;
  size_t arraySize = bytes.size();

  while (totalBytesSent < arraySize) {
    int sentBytes = SSL_write(ssl, bytes.data() + totalBytesSent,
                              (int)(arraySize - totalBytesSent));

    if (sentBytes > 0) {
      totalBytesSent += sentBytes;
    } else {
      int error = SSL_get_error(ssl, sentBytes);
      if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
        if (retryCount < _retryCount) {
          ++retryCount;
          std::this_thread::sleep_for(std::chrono::milliseconds(_sendDelayMS));
          continue;
        } else {
          LogError("Max retries reached while trying to send data");
          break;
        }
        continue;
      } else {
        LogError(GetSSLErrorMessage(error));
        return ERROR;
      }
    }
  }

  return 0;
}

int TcpTransport::Read(void *connection, std::vector<uint8_t> &buffer,
                       uint32_t writeOffset) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retryCount = 0;
  // Implement upper bound for loop
  while (true) {
    int bytesReceived = SSL_read(ssl, buffer.data() + writeOffset,
                                 (int)buffer.capacity() - writeOffset);

    if (bytesReceived == 0) {
      // LogError("Client closed the connection");
      return ERROR;
    } else if (bytesReceived < 0) {
      int error = SSL_get_error(ssl, bytesReceived);

      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (retryCount < _retryCount) {
          ++retryCount;
          std::this_thread::sleep_for(std::chrono::milliseconds(_recvDelayMS));
          continue;
        } else {
          LogError("Max retries reached while trying to receive data");
          return ERROR;
        }
      } else {
        LogError(GetSSLErrorMessage(error));
        return ERROR;
      }
    }
    return bytesReceived;
  }
  return ERROR;
}

int TcpTransport::SendBatch_TS(void *connection,
                               const std::vector<std::vector<uint8_t>> &bytes,
                               std::mutex &mut) {
  for (const auto &chunk : bytes) {
    if (Send_TS(connection, chunk, mut) == ERROR) {
      return ERROR;
    }
  }

  return 0;

  // SSL *ssl = static_cast<SSL *>(connection);
  //
  // for (const auto &chunk : bytes) {
  //   uint32_t retryCount = 0;
  //   size_t totalBytesSent = 0;
  //   size_t arraySize = chunk.size();
  //
  //   while (totalBytesSent < arraySize) {
  //     int sentBytes = 0;
  //     {
  //       std::lock_guard<std::mutex> lock(mut);
  //       sentBytes = SSL_write(ssl, chunk.data() + totalBytesSent,
  //                             (int)(arraySize - totalBytesSent));
  //     }
  //     if (sentBytes > 0) {
  //       totalBytesSent += sentBytes;
  //     } else {
  //       int error = SSL_get_error(ssl, sentBytes);
  //       if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
  //         if (retryCount < _retryCount) {
  //           ++retryCount;
  //           std::this_thread::sleep_for(
  //               std::chrono::milliseconds(_sendDelayMS));
  //           continue;
  //         } else {
  //           LogError("Max retries reached while trying to send data");
  //           break;
  //         }
  //         continue;
  //       } else {
  //         LogError(GetSSLErrorMessage(error));
  //         return ERROR;
  //       }
  //     }
  //   }
  // }
  // return 0;
}

int TcpTransport::Send_TS(void *connection, const std::vector<uint8_t> &bytes,
                          std::mutex &mut) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retryCount = 0;
  size_t totalBytesSent = 0;
  size_t arraySize = bytes.size();

  while (totalBytesSent < arraySize) {
    int sentBytes = 0;
    {
      std::lock_guard<std::mutex> lock(mut);
      sentBytes = SSL_write(ssl, bytes.data() + totalBytesSent,
                            (int)(arraySize - totalBytesSent));
    }

    if (sentBytes > 0) {
      totalBytesSent += sentBytes;
    } else {
      int error = SSL_get_error(ssl, sentBytes);
      if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
        if (retryCount < _retryCount) {
          ++retryCount;
          std::this_thread::sleep_for(std::chrono::milliseconds(_sendDelayMS));
          continue;
        } else {
          LogError("Max retries reached while trying to send data");
          break;
        }
        continue;
      } else {
        LogError(GetSSLErrorMessage(error));
        return ERROR;
      }
    }
  }

  return 0;
}

int TcpTransport::Read_TS(void *connection, std::vector<uint8_t> &buffer,
                          uint32_t writeOffset, std::mutex &mut) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retryCount = 0;
  // Implement upper bound for loop
  while (true) {
    int bytesReceived = 0;
    {
      std::lock_guard<std::mutex> lock(mut);
      bytesReceived = SSL_read(ssl, buffer.data() + writeOffset,
                               (int)buffer.capacity() - writeOffset);
    }
    if (bytesReceived == 0) {
      // LogError("Client closed the connection");
      return ERROR;
    } else if (bytesReceived < 0) {
      int error = SSL_get_error(ssl, bytesReceived);

      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (retryCount < _retryCount) {
          ++retryCount;
          std::this_thread::sleep_for(std::chrono::milliseconds(_recvDelayMS));
          continue;
        } else {
          LogError("Max retries reached while trying to receive data");
          return ERROR;
        }
      } else {
        LogError(GetSSLErrorMessage(error));
        return ERROR;
      }
    }
    return bytesReceived;
  }
  return ERROR;
}

int QuicTransport::SendBatch(void *connection,
                             const std::vector<std::vector<uint8_t>> &bytes) {
  HQUIC stream = static_cast<HQUIC>(connection);

  QUIC_STATUS status;
  uint8_t *sendBufferRaw;
  QUIC_BUFFER *sendBuffer;

  for (const auto &chunk : bytes) {
    sendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + chunk.size());

    if (sendBufferRaw == NULL) {
      LogError("SendBuffer allocation failed");
      status = QUIC_STATUS_OUT_OF_MEMORY;
      if (QUIC_FAILED(status)) {
        MsQuic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return ERROR;
      }
    }

    sendBuffer = (QUIC_BUFFER *)sendBufferRaw;
    sendBuffer->Buffer = sendBufferRaw + sizeof(QUIC_BUFFER);
    sendBuffer->Length = chunk.size();

    memcpy(sendBuffer->Buffer, chunk.data(), chunk.size());

    if (QUIC_FAILED(status = MsQuic->StreamSend(stream, sendBuffer, 1,
                                                (&chunk == &bytes.back())
                                                    ? QUIC_SEND_FLAG_FIN
                                                    : QUIC_SEND_FLAG_DELAY_SEND,
                                                sendBuffer))) {
      std::ostringstream oss;
      oss << "StreamSend failed, 0x" << std::hex << status;
      LogError(oss.str());

      free(sendBufferRaw);
      if (QUIC_FAILED(status)) {
        MsQuic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return ERROR;
      }
    }
  }
  return 0;
}

int QuicTransport::Send(void *connection, const std::vector<uint8_t> &bytes) {
  HQUIC stream = static_cast<HQUIC>(connection);

  QUIC_STATUS status;
  uint8_t *sendBufferRaw;
  QUIC_BUFFER *sendBuffer;

  sendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + bytes.size());

  if (sendBufferRaw == NULL) {
    LogError("SendBuffer allocation failed");
    status = QUIC_STATUS_OUT_OF_MEMORY;
    if (QUIC_FAILED(status)) {
      MsQuic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return ERROR;
    }
  }

  sendBuffer = (QUIC_BUFFER *)sendBufferRaw;
  sendBuffer->Buffer = sendBufferRaw + sizeof(QUIC_BUFFER);
  sendBuffer->Length = bytes.size();

  memcpy(sendBuffer->Buffer, bytes.data(), bytes.size());

  if (QUIC_FAILED(status =
                      MsQuic->StreamSend(stream, sendBuffer, 1,
                                         QUIC_SEND_FLAG_NONE, sendBuffer))) {
    std::ostringstream oss;
    oss << "StreamSend failed, 0x" << std::hex << status;
    LogError(oss.str());

    free(sendBufferRaw);
    if (QUIC_FAILED(status)) {
      MsQuic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return ERROR;
    }
  }

  return 0;
}

int QuicTransport::Read(void *connection, std::vector<uint8_t> &buffer,
                        uint32_t writeOffset) {
  return ERROR;
}

int QuicTransport::SendBatch_TS(void *connection,
                                const std::vector<std::vector<uint8_t>> &bytes,
                                std::mutex &mut) {
  return ERROR;
}

int QuicTransport::Send_TS(void *connection, const std::vector<uint8_t> &bytes,
                           std::mutex &mut) {
  return ERROR;
}

int QuicTransport::Read_TS(void *connection, std::vector<uint8_t> &buffer,
                           uint32_t writeOffset, std::mutex &mut) {
  return ERROR;
}
