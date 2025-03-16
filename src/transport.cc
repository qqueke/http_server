// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/transport.h"

#include <fcntl.h>
#include <openssl/ssl.h>
#include <sys/stat.h>

#include <cstdint>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "../include/log.h"
#include "../include/utils.h"
// #include "crypto.h"
// #include "ssl.h"

TcpTransport::TcpTransport()
    : _retry_count_(MAX_RETRIES),
      _sendDelayMS_(SEND_DELAY_MS),
      _recvDelayMS_(RECV_DELAY_MS) {}

TcpTransport::TcpTransport(uint32_t retry_count, uint32_t sendDelayMS,
                           uint32_t recvDelayMS)
    : _retry_count_(retry_count),
      _sendDelayMS_(sendDelayMS),
      _recvDelayMS_(recvDelayMS) {}

int TcpTransport::SendBatch(void *connection,
                            const std::vector<std::vector<uint8_t>> &bytes) {
  for (const auto &chunk : bytes) {
    if (Send(connection, chunk) == ERROR) {
      return ERROR;
    }
  }

  return 0;
}

int TcpTransport::SendFile(void *connection, int fd) {
  struct stat file_stats{};
  if (fstat(fd, &file_stats) == -1) {
    LogError("Could not read file stats");
    return ERROR;
  }

  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retry_count = 0;
  int64_t totalBytesSent = 0;

  int64_t file_size = file_stats.st_size;

  if (BIO_get_ktls_send(SSL_get_wbio(ssl))) {
    while (totalBytesSent < file_size) {
      int sentBytes =
          SSL_sendfile(ssl, fd, static_cast<int64_t>(totalBytesSent),
                       static_cast<size_t>(file_size - totalBytesSent), 0);

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
  }

  std::vector<uint8_t> bytes(file_size);

  int read_bytes = 0;
  while ((read_bytes = read(fd, bytes.data(), bytes.size())) > 0) {
    totalBytesSent = 0;
    while (static_cast<int>(totalBytesSent) < read_bytes) {
      int sentBytes = SSL_write(ssl, bytes.data() + totalBytesSent,
                                static_cast<int>(read_bytes - totalBytesSent));

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
  }
  return 0;
}

int TcpTransport::Send(void *connection, const std::vector<uint8_t> &bytes) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retry_count = 0;
  size_t totalBytesSent = 0;
  size_t arraySize = bytes.size();

  while (totalBytesSent < arraySize) {
    int sentBytes = SSL_write(ssl, bytes.data() + totalBytesSent,
                              static_cast<int>(arraySize - totalBytesSent));

    if (sentBytes > 0) {
      totalBytesSent += sentBytes;
    } else {
      int error = SSL_get_error(ssl, sentBytes);
      if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
        if (retry_count < _retry_count_) {
          ++retry_count;
          std::this_thread::sleep_for(std::chrono::milliseconds(_sendDelayMS_));
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

int TcpTransport::Read(void *connection, std::vector<uint8_t> &buffer,
                       uint32_t write_offset) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retry_count = 0;
  // Implement upper bound for loop
  while (true) {
    int n_bytes_recv =
        SSL_read(ssl, buffer.data() + write_offset,
                 static_cast<int>(buffer.capacity() - write_offset));

    if (n_bytes_recv == 0) {
      // LogError("Client closed the connection");
      return ERROR;
    } else if (n_bytes_recv < 0) {
      int error = SSL_get_error(ssl, n_bytes_recv);

      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (retry_count < _retry_count_) {
          ++retry_count;
          std::this_thread::sleep_for(std::chrono::milliseconds(_recvDelayMS_));
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
    return n_bytes_recv;
  }
  return ERROR;
}

int TcpTransport::SendBatch(void *connection,
                            const std::vector<std::vector<uint8_t>> &bytes,
                            std::mutex &mut) {
  for (const auto &chunk : bytes) {
    if (Send(connection, chunk, mut) == ERROR) {
      return ERROR;
    }
  }

  return 0;
}

int TcpTransport::Send(void *connection, const std::vector<uint8_t> &bytes,
                       std::mutex &mut) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retry_count = 0;
  size_t totalBytesSent = 0;
  size_t arraySize = bytes.size();

  while (totalBytesSent < arraySize) {
    int sentBytes = 0;
    {
      std::lock_guard<std::mutex> lock(mut);
      sentBytes = SSL_write(ssl, bytes.data() + totalBytesSent,
                            static_cast<int>(arraySize - totalBytesSent));
    }

    if (sentBytes > 0) {
      totalBytesSent += sentBytes;
    } else {
      int error = SSL_get_error(ssl, sentBytes);
      if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
        if (retry_count < _retry_count_) {
          ++retry_count;
          std::this_thread::sleep_for(std::chrono::milliseconds(_sendDelayMS_));
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

int TcpTransport::Read(void *connection, std::vector<uint8_t> &buffer,
                       uint32_t write_offset, std::mutex &mut) {
  SSL *ssl = static_cast<SSL *>(connection);

  uint32_t retry_count = 0;
  // Implement upper bound for loop
  while (true) {
    int n_bytes_recv = 0;
    {
      std::lock_guard<std::mutex> lock(mut);
      n_bytes_recv =
          SSL_read(ssl, buffer.data() + write_offset,
                   static_cast<int>(buffer.capacity() - write_offset));
    }
    if (n_bytes_recv == 0) {
      // LogError("Client closed the connection");
      return ERROR;
    } else if (n_bytes_recv < 0) {
      int error = SSL_get_error(ssl, n_bytes_recv);

      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (retry_count < _retry_count_) {
          ++retry_count;
          std::this_thread::sleep_for(std::chrono::milliseconds(_recvDelayMS_));
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
    return n_bytes_recv;
  }
  return ERROR;
}

int QuicTransport::SendBatch(void *connection,
                             const std::vector<std::vector<uint8_t>> &bytes) {
  const size_t size = bytes.size();

  for (size_t i = 0; i < size; ++i) {
    const auto &chunk = bytes[i];
    bool is_last_chunk = (i == size - 1);

    // Handle chunk
    if (is_last_chunk) {
      if (Send(connection, chunk, QUIC_SEND_FLAG_FIN) == ERROR) {
        return ERROR;
      }

    } else {
      if (Send(connection, chunk) == ERROR) {
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

  sendBufferRaw =
      reinterpret_cast<uint8_t *>(malloc(sizeof(QUIC_BUFFER) + bytes.size()));

  if (sendBufferRaw == NULL) {
    LogError("SendBuffer allocation failed");
    status = QUIC_STATUS_OUT_OF_MEMORY;
    if (QUIC_FAILED(status)) {
      ms_quic_->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return ERROR;
    }
  }

  sendBuffer = reinterpret_cast<QUIC_BUFFER *>(sendBufferRaw);
  sendBuffer->Buffer = sendBufferRaw + sizeof(QUIC_BUFFER);
  sendBuffer->Length = bytes.size();

  memcpy(sendBuffer->Buffer, bytes.data(), bytes.size());

  if (QUIC_FAILED(status =
                      ms_quic_->StreamSend(stream, sendBuffer, 1,
                                           QUIC_SEND_FLAG_NONE, sendBuffer))) {
    std::ostringstream oss;
    oss << "StreamSend failed, 0x" << std::hex << status;
    LogError(oss.str());

    free(sendBufferRaw);
    if (QUIC_FAILED(status)) {
      ms_quic_->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return ERROR;
    }
  }

  return 0;
}

int QuicTransport::Send(void *connection, const std::vector<uint8_t> &bytes,
                        enum QUIC_SEND_FLAGS flag) {
  HQUIC stream = static_cast<HQUIC>(connection);

  QUIC_STATUS status;
  uint8_t *sendBufferRaw;
  QUIC_BUFFER *sendBuffer;

  sendBufferRaw =
      reinterpret_cast<uint8_t *>(malloc(sizeof(QUIC_BUFFER) + bytes.size()));

  if (sendBufferRaw == NULL) {
    LogError("SendBuffer allocation failed");
    status = QUIC_STATUS_OUT_OF_MEMORY;
    if (QUIC_FAILED(status)) {
      ms_quic_->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return ERROR;
    }
  }

  sendBuffer = reinterpret_cast<QUIC_BUFFER *>(sendBufferRaw);
  sendBuffer->Buffer = sendBufferRaw + sizeof(QUIC_BUFFER);
  sendBuffer->Length = bytes.size();

  memcpy(sendBuffer->Buffer, bytes.data(), bytes.size());

  if (QUIC_FAILED(status = ms_quic_->StreamSend(stream, sendBuffer, 1, flag,
                                                sendBuffer))) {
    std::ostringstream oss;
    oss << "StreamSend failed, 0x" << std::hex << status;
    LogError(oss.str());

    free(sendBufferRaw);
    if (QUIC_FAILED(status)) {
      ms_quic_->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      return ERROR;
    }
  }

  return 0;
}

// int QuicTransport::SendBatch_TS(void *connection,
//                                 const std::vector<std::vector<uint8_t>>
//                                 &bytes, std::mutex &mut) {
//   return ERROR;
// }
//
// int QuicTransport::Send_TS(void *connection, const std::vector<uint8_t>
// &bytes,
//                            std::mutex &mut) {
//   return ERROR;
// }
