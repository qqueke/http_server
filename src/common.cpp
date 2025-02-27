#include "common.hpp"

#include <lshpack.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <thread>

#include "err.h"
#include "log.hpp"
#include "lsqpack.h"
#include "sstream"
#include "utils.hpp"

void HTTPBase::dhiUnblocked(void *hblock_ctx) {}

struct lsxpack_header *HTTPBase::dhiPrepareDecode(void *hblock_ctx_p,
                                                  struct lsxpack_header *xhdr,
                                                  size_t space) {
  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx_p;

  if (xhdr != NULL) {
    xhdr->val_len = space;
  } else {
    lsxpack_header_prepare_decode(&block_ctx->xhdr, block_ctx->buf,
                                  block_ctx->buf_off, space);
  }
  return &block_ctx->xhdr;
}

// HTTP1 Request Formatted String to HTTP3 Headers Map
void HTTPBase::ReqHeaderToPseudoHeader(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headersMap) {
  std::istringstream stream(http1Headers);
  std::string line;
  std::string key{};
  std::string value{};
  // std::vector<std::pair<std::string, std::string>> headers;

  // Read the first line (status line in HTTP/1.1)
  while (std::getline(stream, line, '\n')) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    size_t firstSpace = line.find(' ');
    if (firstSpace != std::string::npos) {
      // If we find a second space it is the status header
      size_t secondSpace = line.find(' ', firstSpace + 1);
      if (secondSpace != std::string::npos) {
        key = ":method";
        value = line.substr(0, firstSpace);
        headersMap[key] = value;
        // headers.emplace_back(key, value);

        key = ":scheme";
        value = "https";

        headersMap[key] = value;
        // headers.emplace_back(key, value);

        key = ":path";
        value = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);

        headersMap[key] = value;
        // headers.emplace_back(key, value);

      } else {
        key = line.substr(0, firstSpace - 1);
        value = line.substr(firstSpace + 1);
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        // Remove "Connection" header
        if (key != "connection")
          headersMap[key] = value;
      }
    }
  }
}

// void HTTPBase::HPACK_DecodePartialHeaders(
//     struct lshpack_dec &dec,
//     std::unordered_map<std::string, std::string> &TcpDecodedHeaders,
//     std::vector<uint8_t> &encodedHeaders) {
//   const unsigned char *src = const_cast<unsigned char
//   *>(encodedHeaders.data()); const unsigned char *end = src +
//   encodedHeaders.size();
//
//   struct lsxpack_header headerFormat;
//
//   char headerBuffer[2048] = {};
//
//   while (src < end) {
//     lsxpack_header_prepare_decode(&headerFormat, &headerBuffer[0], 0,
//                                   sizeof(headerBuffer));
//
//     int ret = lshpack_dec_decode(&dec, &src, end, &headerFormat);
//     if (ret < 0) {
//       std::cerr << "Failed to decode HPACK headers" << std::endl;
//       break;
//     }
//
//     // int decodedSize = headerFormat.name_len + headerFormat.val_len +
//     //                   lshpack_dec_extra_bytes(dec);
//
//     TcpDecodedHeaders.emplace(
//         std::string(headerFormat.buf + headerFormat.name_offset,
//                     headerFormat.name_len),
//         std::string(headerFormat.buf + headerFormat.val_offset,
//                     headerFormat.val_len));
//   }
//
//   std::cout << "Decoded headers:\n";
//   for (const auto &[key, value] : TcpDecodedHeaders) {
//     std::cout << key << ": " << value << "\n";
//   }
//   std::cout << std::endl;
// }

void HTTPBase::HPACK_DecodeHeaders(
    struct lshpack_dec &dec,
    std::unordered_map<std::string, std::string> &TcpDecodedHeaders,
    std::vector<uint8_t> &encodedHeaders) {
  const unsigned char *src = const_cast<unsigned char *>(encodedHeaders.data());
  const unsigned char *end = src + encodedHeaders.size();

  struct lsxpack_header headerFormat;

  char headerBuffer[2048] = {};

  while (src < end) {
    lsxpack_header_prepare_decode(&headerFormat, &headerBuffer[0], 0,
                                  sizeof(headerBuffer));

    int ret = lshpack_dec_decode(&dec, &src, end, &headerFormat);
    if (ret < 0) {
      std::cerr << "Failed to decode HPACK headers" << std::endl;
      break;
    }

    // int decodedSize = headerFormat.name_len + headerFormat.val_len +
    //                   lshpack_dec_extra_bytes(dec);

    TcpDecodedHeaders.emplace(
        std::string(headerFormat.buf + headerFormat.name_offset,
                    headerFormat.name_len),
        std::string(headerFormat.buf + headerFormat.val_offset,
                    headerFormat.val_len));
  }

  // std::cout << "Decoded headers:\n";
  // for (const auto &[key, value] : TcpDecodedHeaders) {
  //   std::cout << key << ": " << value << "\n";
  // }
  // std::cout << std::endl;
}

// HTTP1 Response Formatted String to HTTP3 Headers Map

void HTTPBase::RespHeaderToPseudoHeader(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headersMap) {
  std::istringstream stream(http1Headers);
  std::string line;
  // std::string key{};
  // std::string value{};

  // Read the first line (status line in HTTP/1.1)
  while (std::getline(stream, line, '\n')) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    size_t firstSpace = line.find(' ');
    if (firstSpace != std::string::npos) {
      // If we find a second space it is the status header
      size_t secondSpace = line.find(' ', firstSpace + 1);
      if (secondSpace != std::string::npos &&
          headersMap.find(":status") == headersMap.end()) {
        headersMap[":status"] =
            line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        break;
      }

      // else {
      //   key = line.substr(0, firstSpace - 1);
      //   value = line.substr(firstSpace + 1);
      //
      //   std::transform(key.begin(), key.end(), key.begin(),
      //                  [](unsigned char c) { return std::tolower(c); });
      //
      //   // Remove "Connection" header
      //   if (key != "connection")
      //     headersMap[key] = value;
      //   // headers.emplace_back(key, value);
      // }
    }
  }
  //
  // std::cout << "Headers size: " << http1Headers.size()
  //           << " HeadersMap size: " << headersMap.size() << std::endl;
}

int HTTPBase::HTTP3_SendFramesToStream(
    HQUIC Stream, const std::vector<std::vector<uint8_t>> &frames) {
  QUIC_STATUS Status;
  uint8_t *SendBufferRaw;
  QUIC_BUFFER *SendBuffer;

  for (auto &frame : frames) {
    SendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + frame.size());

    if (SendBufferRaw == NULL) {
      LogError("SendBuffer allocation failed");
      Status = QUIC_STATUS_OUT_OF_MEMORY;
      if (QUIC_FAILED(Status)) {
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);

        return -1;
      }
    }

    SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = frame.size();

    memcpy(SendBuffer->Buffer, frame.data(), frame.size());

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1,
                                                (&frame == &frames.back())
                                                    ? QUIC_SEND_FLAG_FIN
                                                    : QUIC_SEND_FLAG_DELAY_SEND,
                                                SendBuffer))) {
      std::ostringstream oss;
      oss << "StreamSend failed, 0x" << std::hex << Status;
      LogError(oss.str());

      free(SendBufferRaw);
      if (QUIC_FAILED(Status)) {
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);

        return ERROR;
      }
    }
  }
  return 0;
}

int HTTPBase::HTTP3_SendFramesToNewConn(
    _In_ HQUIC Connection, HQUIC Stream,
    const std::vector<std::vector<uint8_t>> &frames) {
  QUIC_STATUS Status;
  uint8_t *SendBufferRaw;
  QUIC_BUFFER *SendBuffer;

  for (auto &frame : frames) {
    // const std::vector<uint8_t>& frame = frames[i];

    SendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + frame.size());

    if (SendBufferRaw == NULL) {
      LogError("SendBuffer allocation failed!\n");
      Status = QUIC_STATUS_OUT_OF_MEMORY;
      if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return -1;
      }
    }

    SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = frame.size();

    memcpy(SendBuffer->Buffer, frame.data(), frame.size());

    // Delay on sending the last frame
    // if (&frame == &frames.back()) {
    //   std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    // }

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1,
                                                (&frame == &frames.back())
                                                    ? QUIC_SEND_FLAG_FIN
                                                    : QUIC_SEND_FLAG_DELAY_SEND,
                                                SendBuffer))) {
      std::ostringstream oss;
      oss << "StreamSend failed, 0x" << std::hex << Status;
      LogError(oss.str());
      free(SendBufferRaw);
      if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return -1;
      }
    }
  }
  return frames.size();
}

std::vector<uint8_t> HTTPBase::HTTP3_BuildDataFrame(const std::string &data) {
  // Construct the frame header for Headers
  uint8_t frameType = 0x00; // 0x00 for DATA frame
  uint32_t payloadLength = data.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType);
  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength);

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payloadLength);
  memcpy(framePayload.data(), data.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  uint32_t totalFrameSize = frameHeader.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> frame(totalFrameSize);
  memcpy(frame.data(), frameHeader.data(), frameHeader.size());
  memcpy(frame.data() + frameHeader.size(), framePayload.data(), payloadLength);

  return frame;
}

std::vector<uint8_t>
HTTPBase::HTTP3_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders) {
  // Construct the frame header for Headers
  uint8_t frameType = Frame::HEADERS; // 0x01 for HEADERS frame
  size_t payloadLength = encodedHeaders.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader;

  // Encode the frame type (0x01 for HEADERS frame)
  EncodeVarint(frameHeader, frameType);
  // Encode the frame length (size of the payload)
  EncodeVarint(frameHeader, payloadLength);

  // Frame payload for Headers
  // std::vector<uint8_t> framePayload(payloadLength);
  // memcpy(framePayload.data(), encodedHeaders.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + payloadLength;

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> headerFrame(totalFrameSize);
  headerFrame.resize(totalFrameSize);
  memcpy(headerFrame.data(), frameHeader.data(), frameHeader.size());
  memcpy(headerFrame.data() + frameHeader.size(), encodedHeaders.data(),
         payloadLength);

  return headerFrame;
}

std::vector<uint8_t> HTTPBase::HTTP2_BuildDataFrame(const std::string &data,
                                                    uint32_t streamID) {
  // Could be more if negotiated in SETTINGS frame
  // (Would also require a readjustment in the frame header)

  uint8_t frameType = Frame::DATA;
  uint8_t flags = HTTP2Flags::END_STREAM_FLAG;
  uint32_t payloadLength = data.size();
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;

  frame[3] = frameType;

  frame[4] = flags;

  frame[5] = (streamID >> 24) & 0xFF;
  frame[6] = (streamID >> 16) & 0xFF;
  frame[7] = (streamID >> 8) & 0xFF;
  frame[8] = streamID & 0xFF;

  memcpy(frame.data() + FRAME_HEADER_LENGTH, data.data(), payloadLength);

  return frame;
}

void HTTPBase::HTTP2_FillSettingsFrame(std::vector<uint8_t> &frame,
                                       uint8_t frameFlags) {
  // Construct the frame header for Headers
  // std::vector<uint8_t> payload = {
  //     0x00, 0x03,             // Setting ID: SETTINGS_MAX_CONCURRENT_STREAMS
  //     0x00, 0x00, 0x00, 0x64  // Value: 100
  // };

  uint8_t frameType = 0x04;
  uint8_t streamId = 0;
  uint8_t payloadLength = 0;
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  if (frame.size() != totalFrameSize) {
    frame.resize(totalFrameSize);
  }

  // Frame header
  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;
  frame[3] = frameType;
  frame[4] = frameFlags;
  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  // // Frame payload
  // // Last processed stream id
  // frame[9] = (streamId >> 24) & 0x7F;  // 7-bit prefix for reserved bit
  // frame[10] = (streamId >> 16) & 0xFF;
  // frame[11] = (streamId >> 8) & 0xFF;
  // frame[12] = streamId & 0xFF;
  //
  // // Error Code
  // frame[13] = (errorCode >> 24) & 0xFF;
  // frame[14] = (errorCode >> 16) & 0xFF;
  // frame[15] = (errorCode >> 8) & 0xFF;
  // frame[16] = errorCode & 0xFF;

  // Size must be set accordingly
}

void HTTPBase::HTTP2_FillRstStreamFrame(std::vector<uint8_t> &frame,
                                        uint32_t streamId, uint32_t errorCode) {
  uint8_t frameType = Frame::RST_STREAM;
  uint8_t frameFlags = HTTP2Flags::NONE_FLAG;
  uint8_t payloadLength = 4;
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  if (frame.size() != totalFrameSize) {
    frame.resize(totalFrameSize);
  }

  // Frame header
  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;
  frame[3] = frameType;
  frame[4] = frameFlags;
  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  // Frame payload
  // Error Code
  frame[FRAME_HEADER_LENGTH] = (errorCode >> 24) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 1] = (errorCode >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (errorCode >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = errorCode & 0xFF;

  // Size must be set accordingly
  frame.resize(totalFrameSize);
}

void HTTPBase::HTTP2_FillGoAwayFrame(std::vector<uint8_t> &frame,
                                     uint32_t streamId, uint32_t errorCode) {
  uint8_t frameType = Frame::GOAWAY;
  uint8_t frameFlags = HTTP2Flags::NONE_FLAG;
  uint8_t payloadLength = 8;
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  if (frame.size() != totalFrameSize) {
    frame.resize(totalFrameSize);
  }

  // Frame header
  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;
  frame[3] = frameType;
  frame[4] = frameFlags;
  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  // Frame payload
  // Last processed stream id
  frame[FRAME_HEADER_LENGTH] = (streamId >> 24) & 0x7F;
  frame[FRAME_HEADER_LENGTH + 1] = (streamId >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (streamId >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = streamId & 0xFF;

  // Error Code
  frame[FRAME_HEADER_LENGTH + 4] = (errorCode >> 24) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 5] = (errorCode >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 6] = (errorCode >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 7] = errorCode & 0xFF;

  // Size must be set accordingly
  frame.resize(totalFrameSize);
}

void HTTPBase::HTTP2_FillWindowUpdateFrame(std::vector<uint8_t> &frame,
                                           uint32_t streamId,
                                           uint32_t increment) {
  // Construct the frame header for Headers
  uint8_t frameType = Frame::WINDOW_UPDATE;
  uint8_t payloadLength = 4;
  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  if (frame.size() != totalFrameSize) {
    frame.resize(totalFrameSize);
  }

  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;

  frame[3] = frameType;

  frame[4] = HTTP2Flags::NONE_FLAG;

  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  frame[FRAME_HEADER_LENGTH] = (increment >> 24) & 0x7F;
  frame[FRAME_HEADER_LENGTH + 1] = (increment >> 16) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 2] = (streamId >> 8) & 0xFF;
  frame[FRAME_HEADER_LENGTH + 3] = increment & 0xFF;
}

void HTTPBase::HTTP2_FillHeaderFrame(std::vector<uint8_t> &frame,
                                     uint32_t streamId) {
  // Header can carry END_STREAM and still have CONTINUATION frames
  // sent next
  // Construct the frame header for Headers
  uint8_t frameType = Frame::HEADERS;
  uint32_t payloadLength = frame.size() - FRAME_HEADER_LENGTH;
  uint8_t flags = HTTP2Flags::END_HEADERS_FLAG;

  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;

  frame[3] = frameType;

  frame[4] = flags;

  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;
}

std::vector<uint8_t>
HTTPBase::HTTP2_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders,
                                 uint32_t streamId) {
  // Construct the frame header for Headers
  uint8_t frameType = Frame::HEADERS;
  uint32_t payloadLength = encodedHeaders.size();
  uint8_t flags = HTTP2Flags::END_HEADERS_FLAG;
  // flags |= (1 << 0);

  uint32_t totalFrameSize = FRAME_HEADER_LENGTH + payloadLength;

  std::vector<uint8_t> frame(totalFrameSize);

  frame[0] = (payloadLength >> 16) & 0xFF;
  frame[1] = (payloadLength >> 8) & 0xFF;
  frame[2] = payloadLength & 0xFF;

  frame[3] = frameType;

  frame[4] = flags;

  frame[5] = (streamId >> 24) & 0xFF;
  frame[6] = (streamId >> 16) & 0xFF;
  frame[7] = (streamId >> 8) & 0xFF;
  frame[8] = streamId & 0xFF;

  memcpy(frame.data() + FRAME_HEADER_LENGTH, encodedHeaders.data(),
         payloadLength);

  return frame;
}

int HTTPBase::HTTP1_SendMessage(SSL *clientSSL, const std::string &response) {
  // std::cout << "Sending HTTP1 response" << std::endl;

  size_t totalBytesSent = 0;
  size_t frameSize = response.size();

  while (totalBytesSent < frameSize) {
    int sentBytes = SSL_write(clientSSL, response.data() + totalBytesSent,
                              (int)(frameSize - totalBytesSent));

    if (sentBytes > 0) {
      totalBytesSent += sentBytes;
    } else {
      int error = SSL_get_error(clientSSL, sentBytes);
      if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
        // std::cout << "SSL buffer full, retrying..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      } else {
        LogError("Failed to send HTTP1 response");
        return ERROR;
      }
    }
  }
  return 0;
}

int HTTPBase::HTTP2_SendFrame_TS(SSL *ssl, std::vector<uint8_t> &frame) {
  // std::cout << "Sending HTTP2 response" << std::endl;

  uint8_t frameType = frame[3];
  const int maxRetries = 5;
  size_t totalBytesSent = 0;
  size_t frameSize = frame.size();
  int retryCount = 0;
  int sentBytes = 0;

  while (totalBytesSent < frameSize) {
    {
      std::lock_guard<std::mutex> lock(TCP_MutexMap[ssl]);
      sentBytes = SSL_write(ssl, frame.data() + totalBytesSent,
                            (int)(frameSize - totalBytesSent));
    }

    if (sentBytes > 0) {
      totalBytesSent += sentBytes;
    } else {
      int error = SSL_get_error(ssl, sentBytes);
      if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
        if (retryCount < maxRetries) {
          retryCount++;
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
          continue;
        } else {
          LogError("Max retries reached while trying to receive data");
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

int HTTPBase::HTTP2_SendFrames_TS(SSL *ssl,
                                  std::vector<std::vector<uint8_t>> &frames) {
  // std::cout << "Sending HTTP2 response" << std::endl;

  int sentBytes = 0;
  const int maxRetries = 5;

  for (auto &frame : frames) {
    int retryCount = 0;
    size_t totalBytesSent = 0;
    size_t frameSize = frame.size();

    while (totalBytesSent < frameSize) {
      {
        std::lock_guard<std::mutex> lock(TCP_MutexMap[ssl]);
        sentBytes = SSL_write(ssl, frame.data() + totalBytesSent,
                              (int)(frameSize - totalBytesSent));
      }
      if (sentBytes > 0) {
        totalBytesSent += sentBytes;
      } else {
        int error = SSL_get_error(ssl, sentBytes);
        if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
          // std::cout << "SSL buffer full, retrying..." << std::endl;
          if (retryCount < maxRetries) {
            retryCount++;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
          } else {
            LogError("Max retries reached while trying to receive data");
            break;
          }
          continue;
        } else {
          LogError(GetSSLErrorMessage(error));
          return ERROR;
        }
      }
    }
  }

  return 0;
}

int HTTPBase::HTTP2_SendFrame(SSL *ssl, std::vector<uint8_t> &frame) {
  // std::cout << "Sending HTTP2 response" << std::endl;

  uint8_t frameType = frame[3];
  const int maxRetries = 5;
  size_t totalBytesSent = 0;
  size_t frameSize = frame.size();
  int retryCount = 0;

  while (totalBytesSent < frameSize) {
    int sentBytes = SSL_write(ssl, frame.data() + totalBytesSent,
                              (int)(frameSize - totalBytesSent));

    if (sentBytes > 0) {
      totalBytesSent += sentBytes;
    } else {
      int error = SSL_get_error(ssl, sentBytes);
      if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
        if (retryCount < maxRetries) {
          retryCount++;
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
          continue;
        } else {
          LogError("Max retries reached while trying to receive data");
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

// Implement max tries
int HTTPBase::HTTP2_SendFrames(SSL *ssl,
                               std::vector<std::vector<uint8_t>> &frames) {
  // std::cout << "Sending HTTP2 response" << std::endl;

  const int maxRetries = 5;
  for (auto &frame : frames) {
    size_t totalBytesSent = 0;
    size_t frameSize = frame.size();
    int retryCount = 0;

    while (totalBytesSent < frameSize) {
      int sentBytes = SSL_write(ssl, frame.data() + totalBytesSent,
                                (int)(frameSize - totalBytesSent));

      if (sentBytes > 0) {
        totalBytesSent += sentBytes;
      } else {
        int error = SSL_get_error(ssl, sentBytes);
        if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
          if (retryCount < maxRetries) {
            retryCount++;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
          } else {
            LogError("Max retries reached while trying to receive data");
            break;
          }
          continue;
        } else {
          LogError(GetSSLErrorMessage(error));
          return ERROR;
        }
      }
    }
  }

  return 0;
}

int HTTPBase::HTTP3_SendFrames(HQUIC Stream,
                               std::vector<std::vector<uint8_t>> &frames) {
  // std::cout << "Sending HTTP3 response" << std::endl;
  if (HTTP3_SendFramesToStream(Stream, frames) == ERROR) {
    LogError("Failed to send HTTP3 response");
    return ERROR;
  }

  return 0;
}

void HTTPBase::EncodeVarint(std::vector<uint8_t> &buffer, uint64_t value) {
  if (value <= 63) { // Fit in 1 byte
    buffer.push_back(static_cast<uint8_t>(value));
  } else if (value <= 16383) { // Fit in 2 bytes
    buffer.push_back(
        static_cast<uint8_t>((value >> 8) | 0x40));       // Set prefix 01
    buffer.push_back(static_cast<uint8_t>(value & 0xFF)); // Remaining 8 bits
  } else if (value <= 1073741823) {                       // Fit in 4 bytes
    buffer.push_back(
        static_cast<uint8_t>((value >> 24) | 0x80)); // Set prefix 10
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
  } else if (value <= 4611686018427387903) { // Fit in 8 bytes
    buffer.push_back(
        static_cast<uint8_t>((value >> 56) | 0xC0)); // Set prefix 11
    buffer.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
  }
}

uint64_t HTTPBase::ReadVarint(std::vector<uint8_t>::iterator &iter,
                              const std::vector<uint8_t>::iterator &end) {
  // Check if there's enough data for at least the first byte
  if (iter + 1 >= end) {
    LogError("Buffer overflow in ReadVarint");
    return ERROR;
  }

  // Read the first byte
  uint64_t value = *iter++;
  uint8_t prefix =
      value >> 6; // Get the prefix to determine the length of the varint
  size_t length = 1 << prefix; // 1, 2, 4, or 8 bytes

  value &= 0x3F; // Mask out the 2 most significant bits

  // Check if we have enough data for the full varint
  if (iter + length - 1 >= end) {
    LogError("Error: Not enough data in buffer for full varint\n");
    return ERROR;
  }

  // Read the remaining bytes of the varint
  for (size_t i = 1; i < length; ++i) {
    value = (value << 8) | *iter++;
  }

  return value;
}

void HTTPBase::HPACK_EncodeHeaderIntoFrame(
    struct lshpack_enc &enc,
    const std::unordered_map<std::string, std::string> &headersMap,
    std::vector<uint8_t> &encodedHeaders) {
  unsigned char *dst = encodedHeaders.data() + FRAME_HEADER_LENGTH;
  unsigned char *end = dst + encodedHeaders.size() - FRAME_HEADER_LENGTH;

  char headerBuffer[128];

  struct lsxpack_header headerFormat;

  if (headersMap.find(":status") != headersMap.end()) {
    const std::string &name = ":status";
    const std::string &value = headersMap.at(":status");

    // std::string combinedHeader = name + ": " + value;

    size_t nameLen = name.size();
    size_t valueLen = value.size();

    memcpy(headerBuffer, name.data(), nameLen);
    headerBuffer[nameLen] = ':';
    headerBuffer[nameLen + 1] = ' ';
    memcpy(headerBuffer + nameLen + 2, value.data(), valueLen);

    // std::cout << "Encoding header: " << combinedHeader << std::endl;
    // struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, &headerBuffer[0], 0, nameLen,
                               nameLen + 2, valueLen);

    dst = lshpack_enc_encode(&enc, dst, end, &headerFormat);
  }

  for (const auto &header : headersMap) {
    if (header.first == ":status") {
      continue;
    }

    // auto header = headersMap.begin();
    const std::string &name = header.first;
    const std::string &value = header.second;

    // std::string combinedHeader = name + ": " + value;

    size_t nameLen = name.size();
    size_t valueLen = value.size();

    memcpy(headerBuffer, name.data(), nameLen);
    headerBuffer[nameLen] = ':';
    headerBuffer[nameLen + 1] = ' ';
    memcpy(headerBuffer + nameLen + 2, value.data(), valueLen);

    // std::cout << "Encoding header: " << combinedHeader << std::endl;
    // struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, &headerBuffer[0], 0,
                               name.length(), name.length() + 2, value.size());

    dst = lshpack_enc_encode(&enc, dst, end, &headerFormat);
  }

  encodedHeaders.resize(dst - encodedHeaders.data());
}

void HTTPBase::HPACK_EncodeHeaders(
    struct lshpack_enc &enc,
    const std::unordered_map<std::string, std::string> &headersMap,
    std::vector<uint8_t> &encodedHeaders) {
  // static thread_local unsigned char buf[1024];
  // unsigned char *dst = buf;
  // unsigned char *end = buf + sizeof(buf);

  // encodedHeaders.resize(1024);
  unsigned char *dst = encodedHeaders.data();
  unsigned char *end = dst + encodedHeaders.size();

  char headerBuffer[128];

  struct lsxpack_header headerFormat;

  if (headersMap.find(":status") != headersMap.end()) {
    const std::string &name = ":status";
    const std::string &value = headersMap.at(":status");

    // std::string combinedHeader = name + ": " + value;

    size_t nameLen = name.size();
    size_t valueLen = value.size();

    memcpy(headerBuffer, name.data(), nameLen);
    headerBuffer[nameLen] = ':';
    headerBuffer[nameLen + 1] = ' ';
    memcpy(headerBuffer + nameLen + 2, value.data(), valueLen);

    // std::cout << "Encoding header: " << combinedHeader << std::endl;
    // struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, &headerBuffer[0], 0, nameLen,
                               nameLen + 2, valueLen);

    dst = lshpack_enc_encode(&enc, dst, end, &headerFormat);
  }

  for (const auto &header : headersMap) {
    if (header.first == ":status") {
      continue;
    }

    // auto header = headersMap.begin();
    const std::string &name = header.first;
    const std::string &value = header.second;

    // std::string combinedHeader = name + ": " + value;

    size_t nameLen = name.size();
    size_t valueLen = value.size();

    memcpy(headerBuffer, name.data(), nameLen);
    headerBuffer[nameLen] = ':';
    headerBuffer[nameLen + 1] = ' ';
    memcpy(headerBuffer + nameLen + 2, value.data(), valueLen);

    // std::cout << "Encoding header: " << combinedHeader << std::endl;
    // struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, &headerBuffer[0], 0,
                               name.length(), name.length() + 2, value.size());

    dst = lshpack_enc_encode(&enc, dst, end, &headerFormat);
  }

  encodedHeaders.resize(dst - encodedHeaders.data());

  // Get rid of this
  // encodedHeaders.assign(buf, dst);
}

void HTTPBase::QPACK_EncodeHeaders(
    uint64_t streamId, std::unordered_map<std::string, std::string> &headersMap,
    std::vector<uint8_t> &encodedHeaders) {
  // Prepare encoding context for QPACK (Header encoding for QUIC)
  std::vector<struct lsqpack_enc> enc(1);

  size_t stdcBufSize = 1024;

  std::vector<unsigned char> sdtcBuf(1024);

  lsqpack_enc_opts encOpts{};

  int ret =
      lsqpack_enc_init(enc.data(), NULL, 0x1000, 0x1000, 0,
                       LSQPACK_ENC_OPT_SERVER, sdtcBuf.data(), &stdcBufSize);

  if (ret != 0) {
    std::cerr << "Error initializing encoder." << std::endl;
    return;
  }

  //
  // HERE
  ret = lsqpack_enc_start_header(enc.data(), streamId, 0);

  enum lsqpack_enc_status encStatus;

  std::vector<std::pair<std::vector<unsigned char>, size_t>> encodedHeadersInfo;
  // Iterate through the headersMap and encode each header

  size_t headerSize = 1024;
  size_t totalHeaderSize = 0;

  // Status needs to be sent first (curl HTTP2 seems to not work otherwise)
  {
    const std::string &name = ":status";
    const std::string &value = headersMap[":status"];

    std::string combinedHeader = name + ": " + value;

    struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, combinedHeader.c_str(), 0,
                               name.length(), name.length() + 2, value.size());

    size_t encSize = 1024;
    std::vector<unsigned char> encBuf(encSize);

    lsqpack_enc_flags enc_flags{};

    encodedHeadersInfo.emplace_back(std::vector<unsigned char>(headerSize),
                                    headerSize);

    encStatus = lsqpack_enc_encode(enc.data(), encBuf.data(), &encSize,
                                   encodedHeadersInfo.back().first.data(),
                                   &encodedHeadersInfo.back().second,
                                   &headerFormat, enc_flags);

    totalHeaderSize += encodedHeadersInfo.back().second;
  }

  for (const auto &header : headersMap) {
    // auto header = headersMap.begin();
    if (header.first == ":status")
      continue;

    const std::string &name = header.first;
    const std::string &value = header.second;

    std::string combinedHeader = name + ": " + value;

    struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, combinedHeader.c_str(), 0,
                               name.length(), name.length() + 2, value.size());

    size_t encSize = 1024;
    std::vector<unsigned char> encBuf(encSize);

    lsqpack_enc_flags enc_flags{};

    encodedHeadersInfo.emplace_back(std::vector<unsigned char>(headerSize),
                                    headerSize);

    encStatus = lsqpack_enc_encode(enc.data(), encBuf.data(), &encSize,
                                   encodedHeadersInfo.back().first.data(),
                                   &encodedHeadersInfo.back().second,
                                   &headerFormat, enc_flags);

    totalHeaderSize += encodedHeadersInfo.back().second;
  }

  std::vector<unsigned char> endHeaderBuf(headerSize);

  size_t endHeaderSize =
      lsqpack_enc_end_header(enc.data(), endHeaderBuf.data(), headerSize, NULL);

  totalHeaderSize += endHeaderSize;

  encodedHeaders.resize(totalHeaderSize);
  const unsigned char *encodedHeadersPtr = encodedHeaders.data();

  memcpy(encodedHeaders.data(), endHeaderBuf.data(), endHeaderSize);

  totalHeaderSize = endHeaderSize;
  for (auto &headerInfo : encodedHeadersInfo) {
    unsigned char *headerPointer = headerInfo.first.data();
    size_t currHeaderSize = headerInfo.second;
    memcpy(encodedHeaders.data() + totalHeaderSize, headerPointer,
           currHeaderSize);
    totalHeaderSize += currHeaderSize;
  }

  lsqpack_enc_cleanup(enc.data());
}
