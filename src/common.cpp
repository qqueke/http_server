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

void HTTPBase::HPACK_DecodeHeaders(uint32_t streamId,
                                   std::vector<uint8_t> &encodedHeaders) {
  // std::cout << "encodedHeaders size: " << std::dec << encodedHeaders.size()
  //           << std::endl;
  std::unordered_map<std::string, std::string> decodedHeaders;
  struct lshpack_dec dec{};
  lshpack_dec_init(&dec);

  const unsigned char *src = const_cast<unsigned char *>(encodedHeaders.data());
  const unsigned char *end = src + encodedHeaders.size();

  struct lsxpack_header headerFormat;
  char headerBuffer[2048];
  memset(headerBuffer, 0, sizeof(headerBuffer));

  char name[256], value[1024];

  while (src < end) {
    lsxpack_header_prepare_decode(&headerFormat, headerBuffer, 0,
                                  sizeof(headerBuffer));

    int ret = lshpack_dec_decode(&dec, &src, end, &headerFormat);
    if (ret < 0) {
      std::cerr << "Failed to decode HPACK headers" << std::endl;
      break;
    }

    int decodedSize = headerFormat.name_len + headerFormat.val_len +
                      lshpack_dec_extra_bytes(dec);

    // Copy decoded name and value
    strncpy(name, headerFormat.buf + headerFormat.name_offset,
            headerFormat.name_len);
    name[headerFormat.name_len] = '\0';

    strncpy(value, headerFormat.buf + headerFormat.val_offset,
            headerFormat.val_len);
    value[headerFormat.val_len] = '\0';

    TcpDecodedHeadersMap[streamId][name] = value;
    // decodedHeaders[name] = value;
  }

  // for (const auto &header : TcpDecodedHeadersMap[streamId]) {
  //   std::cout << header.first << ": " << header.second << std::endl;
  // }

  lshpack_dec_cleanup(&dec);
}

// HTTP1 Response Formatted String to HTTP3 Headers Map
void HTTPBase::RespHeaderToPseudoHeader(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headersMap) {
  std::istringstream stream(http1Headers);
  std::string line;
  std::string key{};
  std::string value{};
  std::vector<std::pair<std::string, std::string>> headers;

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
        key = ":status";
        value = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        // headers.emplace_back(key, value);
        headersMap[key] = value;

      } else {
        key = line.substr(0, firstSpace - 1);
        value = line.substr(firstSpace + 1);

        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        // Remove "Connection" header
        if (key != "connection")
          headersMap[key] = value;
        // headers.emplace_back(key, value);
      }
    }
  }
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
  size_t payloadLength = data.size();

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
  size_t totalFrameSize = frameHeader.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> dataFrame(totalFrameSize);
  memcpy(dataFrame.data(), frameHeader.data(), frameHeader.size());
  memcpy(dataFrame.data() + frameHeader.size(), framePayload.data(),
         payloadLength);

  return dataFrame;
}

std::vector<uint8_t>
HTTPBase::HTTP3_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders) {
  // Construct the frame header for Headers
  uint8_t frameType = 0x01; // 0x01 for HEADERS frame
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
  const size_t MAX_FRAME_SIZE = 16384;

  // Construct the frame header for Headers
  uint8_t frameType = 0x00; // 0x00 for DATA frame
  // uint8_t flags = 0x00; // No flags

  uint8_t flags = 0x01; // END_STREAM
  size_t payloadLength = data.size();

  // Header Frame : Type, Length
  std::vector<uint8_t> frameHeader(9, 0); // 9 bytes total

  frameHeader[0] = (payloadLength >> 16) & 0xFF;
  frameHeader[1] = (payloadLength >> 8) & 0xFF;
  frameHeader[2] = payloadLength & 0xFF;

  frameHeader[3] = frameType;

  frameHeader[4] = flags;

  frameHeader[5] = (streamID >> 24) & 0xFF;
  frameHeader[6] = (streamID >> 16) & 0xFF;
  frameHeader[7] = (streamID >> 8) & 0xFF;
  frameHeader[8] = streamID & 0xFF;

  // Frame payload for Headers
  std::vector<uint8_t> framePayload(payloadLength);
  memcpy(framePayload.data(), data.c_str(), payloadLength);

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + framePayload.size();

  // Complete Header frame (frame header + frame payload)
  std::vector<uint8_t> dataFrame(totalFrameSize);
  memcpy(dataFrame.data(), frameHeader.data(), frameHeader.size());
  memcpy(dataFrame.data() + frameHeader.size(), framePayload.data(),
         payloadLength);

  return dataFrame;
}

std::vector<uint8_t> HTTPBase::HTTP2_BuildGoAwayFrame(uint32_t streamId,
                                                      uint32_t errorCode) {
  uint8_t frameType = 0x07;

  std::vector<uint8_t> payload(8, 0);

  payload[0] = (streamId >> 24) & 0x7F; // 7-bit prefix for reserved bit
  payload[1] = (streamId >> 16) & 0xFF;
  payload[2] = (streamId >> 8) & 0xFF;
  payload[3] = streamId & 0xFF;

  // Error Code
  payload[4] = (errorCode >> 24) & 0xFF;
  payload[5] = (errorCode >> 16) & 0xFF;
  payload[6] = (errorCode >> 8) & 0xFF;
  payload[7] = errorCode & 0xFF;

  size_t payloadLength = payload.size();

  // size_t payloadLength = payload.size();
  uint8_t frameFlags = 0x0;

  std::vector<uint8_t> frameHeader(9, 0); // 9 bytes total

  frameHeader[0] = (payloadLength >> 16) & 0xFF;
  frameHeader[1] = (payloadLength >> 8) & 0xFF;
  frameHeader[2] = payloadLength & 0xFF;

  frameHeader[3] = frameType;

  frameHeader[4] = frameFlags;

  frameHeader[5] = (streamId >> 24) & 0xFF;
  frameHeader[6] = (streamId >> 16) & 0xFF;
  frameHeader[7] = (streamId >> 8) & 0xFF;
  frameHeader[8] = streamId & 0xFF;

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + payloadLength;

  std::vector<uint8_t> frame;
  frame.insert(frame.end(), frameHeader.begin(), frameHeader.end());
  frame.insert(frame.end(), payload.begin(), payload.end());

  return frame;
}

std::vector<uint8_t> HTTPBase::HTTP2_BuildSettingsFrame(uint8_t frameFlags) {
  uint32_t streamId = 0;
  // Construct the frame header for Headers
  uint8_t frameType = 0x04; // 0x01 for HEADERS frame
  std::vector<uint8_t> payload = {
      0x00, 0x03,            // Setting ID: SETTINGS_MAX_CONCURRENT_STREAMS
      0x00, 0x00, 0x00, 0x64 // Value: 100
  };

  // size_t payloadLength = payload.size();

  size_t payloadLength = 0;
  // Header can carry END_STREAM and still have CONTINUATION frames
  // sent next
  // 0x01
  std::vector<uint8_t> frameHeader(9, 0); // 9 bytes total

  frameHeader[0] = (payloadLength >> 16) & 0xFF;
  frameHeader[1] = (payloadLength >> 8) & 0xFF;
  frameHeader[2] = payloadLength & 0xFF;

  frameHeader[3] = frameType;

  frameHeader[4] = frameFlags;

  frameHeader[5] = (streamId >> 24) & 0xFF;
  frameHeader[6] = (streamId >> 16) & 0xFF;
  frameHeader[7] = (streamId >> 8) & 0xFF;
  frameHeader[8] = streamId & 0xFF;

  // Combine the Frame Header and Payload into one buffer
  size_t totalFrameSize = frameHeader.size() + payloadLength;

  std::vector<uint8_t> settingsFrame;
  settingsFrame.insert(settingsFrame.end(), frameHeader.begin(),
                       frameHeader.end());
  // settingsFrame.insert(settingsFrame.end(), payload.begin(), payload.end());

  return frameHeader;
}

std::vector<uint8_t>
HTTPBase::HTTP2_BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders,
                                 uint32_t streamId) {
  // Construct the frame header for Headers
  uint8_t frameType = 0x01; // 0x01 for HEADERS frame
  size_t payloadLength = encodedHeaders.size();
  // streamId++;
  // Header can carry END_STREAM and still have CONTINUATION frames
  // sent next
  uint8_t flags = 0x04; // END_HEADERS
  // flags |= (1 << 0);

  std::vector<uint8_t> frameHeader(9, 0); // 9 bytes total

  frameHeader[0] = (payloadLength >> 16) & 0xFF;
  frameHeader[1] = (payloadLength >> 8) & 0xFF;
  frameHeader[2] = payloadLength & 0xFF;

  frameHeader[3] = frameType;

  frameHeader[4] = flags;

  frameHeader[5] = (streamId >> 24) & 0xFF;
  frameHeader[6] = (streamId >> 16) & 0xFF;
  frameHeader[7] = (streamId >> 8) & 0xFF;
  frameHeader[8] = streamId & 0xFF;

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

int HTTPBase::HTTP1_SendMessage(SSL *clientSSL, const std::string &response) {
  std::cout << "Sending HTTP1 response" << std::endl;

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
        std::cout << "SSL buffer full, retrying..." << std::endl;
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

void HTTPBase::HTTP2_RecvFrames_TS(SSL *ssl) {
  // Buffer for encoded headers until decoding
  std::unordered_map<uint32_t, std::vector<uint8_t>> EncodedHeadersBufferMap;

  std::unordered_map<uint32_t, std::string> TcpDataMap;

  // SSL_read buffers
  std::vector<uint8_t> buffer;
  std::vector<uint8_t> tmpBuffer(BUFFER_SIZE);

  const size_t FRAME_HEADER_LENGTH = 9;
  int offset = 0;

  int bytesReceived{};
  bool GOAWAY = false;
  size_t nResponses = 0;
  while (!GOAWAY) {
    {
      std::lock_guard<std::mutex> lock(TCP_MutexMap[ssl]);
      bytesReceived = SSL_read(ssl, tmpBuffer.data(), (int)tmpBuffer.size());
    }

    if (bytesReceived == 0) {
      LogError("Peer closed the connection");
      std::cout << "Peer closed the connection" << std::endl;
      break;
    } else if (bytesReceived < 0) {
      int ssl_error = SSL_get_error(ssl, bytesReceived);

      // Check if it was a timeout
      if (ssl_error == SSL_ERROR_WANT_READ ||
          ssl_error == SSL_ERROR_WANT_WRITE) {
        // Timeout, let's wait for a bit and retry
        std::cout << "Timeout occurred, retrying..." << std::endl;
        std::this_thread::sleep_for(
            std::chrono::milliseconds(100)); // Wait for 100ms before retrying
        continue;                            // Retry reading
      } else {
        LogError("Failed to receive data, OpenSSL error: " +
                 std::to_string(ssl_error));
        std::cout << "Failed to receive data, OpenSSL error: " << ssl_error
                  << std::endl;
        break;
      }
    }

    buffer.insert(buffer.end(), tmpBuffer.begin(),
                  tmpBuffer.begin() + bytesReceived);

    // If we received atleast the frame header
    while (offset + FRAME_HEADER_LENGTH <= buffer.size() && !GOAWAY) {
      uint8_t *framePtr = buffer.data() + offset;

      uint32_t payloadLength = (static_cast<uint32_t>(framePtr[0]) << 16) |
                               (static_cast<uint32_t>(framePtr[1]) << 8) |
                               static_cast<uint32_t>(framePtr[2]);

      if (offset + FRAME_HEADER_LENGTH + payloadLength > buffer.size()) {
        break;
      }

      uint8_t frameType = framePtr[3];

      uint8_t frameFlags = framePtr[4];

      uint32_t frameStream = (framePtr[5] << 24) | (framePtr[6] << 16) |
                             (framePtr[7] << 8) | framePtr[8];

      std::cout << "Payload Length: " << std::dec << (int)payloadLength
                << std::hex << ", Flags: " << (int)frameFlags << " ";

      switch (frameType) {
      case Frame::DATA:
        std::cout << "[strm][" << frameStream << "] DATA frame\n";

        TcpDataMap[frameStream] += std::string(
            reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
            payloadLength);

        std::cout << TcpDataMap[frameStream] << std::endl;

        if (isFlagSet(frameFlags, END_STREAM_FLAG)) {
          // HTTPServer::ValidatePseudoHeaders(TcpDecodedHeadersMap[frameStream]);

          std::cout << "Response:\n";
          for (const auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
            std::cout << key << ": " << value << "\n";
          }
          std::cout << TcpDataMap[frameStream] << "\n";

          TcpDecodedHeadersMap.erase(frameStream);
          EncodedHeadersBufferMap.erase(frameStream);
          ++nResponses;
        }
        break;
      case Frame::HEADERS:
        std::cout << "[strm][" << frameStream << "] HEADERS frame\n";

        {
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payloadLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and dispatch request
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);

            // HTTPServer::ValidatePseudoHeaders(
            //     TcpDecodedHeadersMap[frameStream]);

            std::cout << "Response:\n";
            for (const auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
              std::cout << key << ": " << value << "\n";
            }

            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);
            ++nResponses;
          } else if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and wait for request body
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);
          }
        }
        break;
      case Frame::PRIORITY:
        // std::cout << "[strm][" << frameStream << "] PRIORITY frame\n";

        break;
      case 0x03:
        // std::cout << "[strm][" << frameStream
        //           << "] Received RST_STREAM frame\n";

        TcpDecodedHeadersMap.erase(frameStream);
        EncodedHeadersBufferMap.erase(frameStream);
        break;

      case Frame::SETTINGS:

        // std::cout << "[strm][" << frameStream << "] SETTINGS frame\n";

        // Only respond with an ACK to their SETTINGS frame with no ACK
        if (frameFlags == HTTP2Flags::NONE_FLAG) {
          std::vector<std::vector<uint8_t>> frames;
          frames.emplace_back(HTTPBase::HTTP2_BuildSettingsFrame(
              HTTP2Flags::SETTINGS_ACK_FLAG));
          HTTPBase::HTTP2_SendFrames_TS(ssl, frames);
        }

        break;
      case Frame::GOAWAY:

        std::cout << "[strm][" << frameStream << "] GOAWAY frame\n";
        GOAWAY = true;
        TcpDecodedHeadersMap.erase(frameStream);
        EncodedHeadersBufferMap.erase(frameStream);
        break;

      case Frame::WINDOW_UPDATE:

        std::cout << "[strm][" << frameStream << "] WINDOW_UPDATE frame\n";

        break;

      case Frame::CONTINUATION:

        std::cout << "[strm][" << frameStream << "] CONTINUATION frame\n";
        {
          EncodedHeadersBufferMap[frameStream].insert(
              EncodedHeadersBufferMap[frameStream].end(),
              framePtr + FRAME_HEADER_LENGTH,
              framePtr + FRAME_HEADER_LENGTH + payloadLength);

          if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
              isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and dispatch request
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);

            std::cout << "Response:\n";
            for (const auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
              std::cout << key << ": " << value << "\n";
            }

            TcpDecodedHeadersMap.erase(frameStream);
            EncodedHeadersBufferMap.erase(frameStream);
            ++nResponses;
          } else if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
            // Decode and wait for request body
            HPACK_DecodeHeaders(frameStream,
                                EncodedHeadersBufferMap[frameStream]);
          }
        }
        break;

      default:
        std::cout << "[strm][" << frameStream << "] Unknown frame type: 0x"
                  << std::dec << frameType << std::dec << "\n";
        break;
      }
      // Move the offset to the next frame
      offset += FRAME_HEADER_LENGTH + payloadLength;
    }

    if (offset == buffer.size()) {
      buffer.clear();
      offset = 0;
    }
  }
  std::cout << "Received: " << nResponses << "\n";
}

int HTTPBase::HTTP2_SendFrames_TS(SSL *ssl,
                                  std::vector<std::vector<uint8_t>> &frames) {
  std::cout << "Sending HTTP2 response" << std::endl;

  int sentBytes;
  const int maxRetries = 5;
  for (auto &frame : frames) {
    size_t totalBytesSent = 0;
    size_t frameSize = frame.size();
    int retryCount = 0;

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
          std::cout << "SSL buffer full, retrying..." << std::endl;
          std::this_thread::sleep_for(std::chrono::milliseconds(10));

          continue;
        } else {
          unsigned long errCode = ERR_get_error();
          char errorString[120];
          ERR_error_string_n(errCode, errorString, sizeof(errorString));

          // Map SSL error code to a human-readable message
          std::string sslErrorMsg;
          switch (error) {
          case SSL_ERROR_NONE:
            sslErrorMsg = "No error occurred.";
            break;
          case SSL_ERROR_ZERO_RETURN:
            sslErrorMsg = "SSL connection was closed cleanly.";
            break;
          case SSL_ERROR_WANT_X509_LOOKUP:
            sslErrorMsg = "Operation blocked waiting for certificate lookup.";
            break;
          case SSL_ERROR_SYSCALL:
            sslErrorMsg = "System call failure or connection reset. " +
                          std::string(errorString);
            break;
          case SSL_ERROR_SSL:
            sslErrorMsg =
                "Low-level SSL library error. " + std::string(errorString);
            break;
          default:
            sslErrorMsg = "Unknown SSL error. " + std::string(errorString);
            break;
          }

          std::cout << "Failed to send HTTP2 response fully" << std::endl;
          // Log more verbose error
          LogError("Failed to send HTTP2 frame. SSL Error: " + sslErrorMsg +
                   " (SSL_get_error: " + std::to_string(error) + ")");
          return ERROR;
        }
      }
    }
  }

  return 0;
}

int HTTPBase::HTTP2_SendFrames(SSL *clientSSL,
                               std::vector<std::vector<uint8_t>> &frames) {
  std::cout << "Sending HTTP2 response" << std::endl;

  int sentBytes;
  const int maxRetries = 5;
  for (auto &frame : frames) {
    size_t totalBytesSent = 0;
    size_t frameSize = frame.size();
    int retryCount = 0;

    while (totalBytesSent < frameSize) {
      {
        sentBytes = SSL_write(clientSSL, frame.data() + totalBytesSent,
                              (int)(frameSize - totalBytesSent));
      }
      if (sentBytes > 0) {
        totalBytesSent += sentBytes;
      } else {
        int error = SSL_get_error(clientSSL, sentBytes);
        if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
          std::cout << "SSL buffer full, retrying..." << std::endl;
          std::this_thread::sleep_for(std::chrono::milliseconds(10));

          continue;
        } else {
          unsigned long errCode = ERR_get_error();
          char errorString[120];
          ERR_error_string_n(errCode, errorString, sizeof(errorString));

          // Map SSL error code to a human-readable message
          std::string sslErrorMsg;
          switch (error) {
          case SSL_ERROR_NONE:
            sslErrorMsg = "No error occurred.";
            break;
          case SSL_ERROR_ZERO_RETURN:
            sslErrorMsg = "SSL connection was closed cleanly.";
            break;
          case SSL_ERROR_WANT_X509_LOOKUP:
            sslErrorMsg = "Operation blocked waiting for certificate lookup.";
            break;
          case SSL_ERROR_SYSCALL:
            sslErrorMsg = "System call failure or connection reset. " +
                          std::string(errorString);
            break;
          case SSL_ERROR_SSL:
            sslErrorMsg =
                "Low-level SSL library error. " + std::string(errorString);
            break;
          default:
            sslErrorMsg = "Unknown SSL error. " + std::string(errorString);
            break;
          }

          std::cout << "Failed to send HTTP2 response fully" << std::endl;
          // Log more verbose error
          LogError("Failed to send HTTP2 frame. SSL Error: " + sslErrorMsg +
                   " (SSL_get_error: " + std::to_string(error) + ")");
          return ERROR;
        }
      }
    }
  }

  return 0;
}

int HTTPBase::HTTP3_SendFrames(HQUIC Stream,
                               std::vector<std::vector<uint8_t>> &frames) {
  std::cout << "Sending HTTP3 response" << std::endl;
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

void HTTPBase::HPACK_EncodeHeaders(
    std::unordered_map<std::string, std::string> &headersMap,
    std::vector<uint8_t> &encodedHeaders) {
  struct lshpack_enc enc{};

  unsigned char buf[1024]; // Buffer for encoded headers
  unsigned char *dst = buf;
  unsigned char *end = buf + sizeof(buf);

  lshpack_enc_init(&enc);

  {
    const std::string &name = ":status";
    const std::string &value = headersMap[":status"];

    std::string combinedHeader = name + ": " + value;
    // std::cout << "Encoding header: " << combinedHeader << std::endl;
    struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, combinedHeader.c_str(), 0,
                               name.length(), name.length() + 2, value.size());

    dst = lshpack_enc_encode(&enc, dst, end, &headerFormat);
  }

  for (const auto &header : headersMap) {
    if (header.first == ":status") {
      continue;
    }

    // auto header = headersMap.begin();
    const std::string &name = header.first;
    const std::string &value = header.second;

    std::string combinedHeader = name + ": " + value;
    // std::cout << "Encoding header: " << combinedHeader << std::endl;
    struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, combinedHeader.c_str(), 0,
                               name.length(), name.length() + 2, value.size());

    dst = lshpack_enc_encode(&enc, dst, end, &headerFormat);
  }

  encodedHeaders.assign(buf, dst);

  lshpack_enc_cleanup(&enc);
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
