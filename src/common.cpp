#include "common.hpp"

#include <lshpack.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <thread>

#include "err.h"
#include "framebuilder.hpp"
#include "log.hpp"
#include "lsqpack.h"
#include "sstream"
#include "utils.hpp"

HttpCore::HttpCore() {
  hpackCodec = std::make_unique<HpackCodec>();
  qpackCodec = std::make_unique<QpackCodec>();

  http2FrameBuilder = std::make_unique<Http2FrameBuilder>();
  http3FrameBuilder = std::make_unique<Http3FrameBuilder>();

  tcpTransport = std::make_unique<TcpTransport>();
  quicTransport = std::make_unique<QuicTransport>();
}

void HttpCore::EncodeHPACKHeaders(
    lshpack_enc &encoder,
    const std::unordered_map<std::string, std::string> &headers,
    std::vector<uint8_t> &encodedHeaders) {
  hpackCodec->Encode(static_cast<void *>(&encoder), headers, encodedHeaders);
}

void HttpCore::DecodeHPACKHeaders(
    lshpack_dec &decoder, std::vector<uint8_t> &encodedHeaders,
    std::unordered_map<std::string, std::string> &decodedHeaders) {
  hpackCodec->Decode(static_cast<void *>(&decoder), encodedHeaders,
                     decodedHeaders);
}

void HttpCore::EncodeQPACKHeaders(
    HQUIC *stream, const std::unordered_map<std::string, std::string> &headers,
    std::vector<uint8_t> &encodedHeaders) {
  qpackCodec->Encode(static_cast<void *>(stream), headers, encodedHeaders);
}

void HttpCore::DecodeQPACKHeaders(
    HQUIC *stream, std::vector<uint8_t> &encodedHeaders,
    std::unordered_map<std::string, std::string> &decodedHeaders) {
  qpackCodec->Decode(static_cast<void *>(stream), encodedHeaders,
                     decodedHeaders);
}

std::vector<uint8_t>
HttpCore::BuildHttp2Frame(Frame type, uint8_t frameFlags, uint32_t streamId,
                          uint32_t errorCode, uint32_t increment,
                          const std::vector<uint8_t> &encodedHeaders,
                          const std::string &data) {
  switch (type) {
  case Frame::DATA:
    return http2FrameBuilder->BuildDataFrame(data, streamId);
  case Frame::HEADERS:
    return http2FrameBuilder->BuildHeaderFrame(encodedHeaders, streamId);
  case Frame::GOAWAY: {
    return http2FrameBuilder->BuildGoAwayFrame(streamId, errorCode);
  }
  case Frame::SETTINGS: {
    return http2FrameBuilder->BuildSettingsFrame(frameFlags);
  }
  case Frame::RST_STREAM: {
    return http2FrameBuilder->BuildRstStreamFrame(streamId, errorCode);
  }
  case Frame::WINDOW_UPDATE: {
    return http2FrameBuilder->BuildWindowUpdateFrame(streamId, increment);
  }
  }

  return {};
}

std::vector<uint8_t>
HttpCore::BuildHttp3Frame(Frame type, uint32_t streamOrPushId,
                          const std::vector<uint8_t> &encodedHeaders,
                          const std::string &data) {
  switch (type) {
  case Frame::DATA:
    return http3FrameBuilder->BuildDataFrame(data);
  case Frame::HEADERS:
    return http3FrameBuilder->BuildHeaderFrame(encodedHeaders);
  case Frame::GOAWAY: {
    return http3FrameBuilder->BuildGoAwayFrame(streamOrPushId);
  }
  case Frame::SETTINGS: {
    return http3FrameBuilder->BuildSettingsFrame();
  }
  }

  return {};
}

int HttpCore::Send(void *connection, const std::vector<uint8_t> &bytes,
                   bool useQuic) {
  if (useQuic) {
    return quicTransport->Send(connection, bytes);
  } else {
    return tcpTransport->Send(connection, bytes);
  }
}

int HttpCore::SendBatch(void *connection,
                        const std::vector<std::vector<uint8_t>> &bytes,
                        bool useQuic) {
  if (useQuic) {
    return quicTransport->SendBatch(connection, bytes);
  } else {
    return tcpTransport->SendBatch(connection, bytes);
  }
}

int HttpCore::Receive(void *connection, std::vector<uint8_t> &buffer,
                      uint32_t writeOffset, bool useQuic) {
  if (useQuic) {
    return quicTransport->Read(connection, buffer, writeOffset);
  } else {
    return tcpTransport->Read(connection, buffer, writeOffset);
  }
}

int HttpCore::Send_TS(void *connection, const std::vector<uint8_t> &bytes,
                      std::mutex &mut, bool useQuic) {
  if (useQuic) {
    return quicTransport->Send_TS(connection, bytes, mut);
  } else {
    return tcpTransport->Send_TS(connection, bytes, mut);
  }
}

int HttpCore::SendBatch_TS(void *connection,
                           const std::vector<std::vector<uint8_t>> &bytes,
                           std::mutex &mut, bool useQuic) {
  if (useQuic) {
    return quicTransport->SendBatch_TS(connection, bytes, mut);
  } else {
    return tcpTransport->SendBatch_TS(connection, bytes, mut);
  }
}

int HttpCore::Receive_TS(void *connection, std::vector<uint8_t> &buffer,
                         uint32_t writeOffset, std::mutex &mut, bool useQuic) {
  if (useQuic) {
    return quicTransport->Read_TS(connection, buffer, writeOffset, mut);
  } else {
    return tcpTransport->Read_TS(connection, buffer, writeOffset, mut);
  }
}

// HTTP1 Request Formatted String to HTTP3 Headers Map
void HttpCore::ReqHeaderToPseudoHeader(
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

// HTTP1 Response Formatted String to HTTP3 Headers Map

void HttpCore::RespHeaderToPseudoHeader(
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

// int HttpCore::HTTP1_SendFile(SSL *ssl, const std::string &filePath) {
//   // std::cout << "Sending HTTP1 response" << std::endl;
//
//   size_t totalBytesSent = 0;
//   size_t responseSize = response.size();
//   int retryCount = 0;
//
//   while (totalBytesSent < responseSize) {
//     int sentBytes = SSL_write(ssl, response.data() + totalBytesSent,
//                               (int)(responseSize - totalBytesSent));
//
//     if (sentBytes > 0) {
//       totalBytesSent += sentBytes;
//     } else {
//       int error = SSL_get_error(ssl, sentBytes);
//       if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
//         if (retryCount < MAX_RETRIES) {
//           retryCount++;
//           std::this_thread::sleep_for(std::chrono::milliseconds(SEND_DELAY_MS));
//           continue;
//         } else {
//           LogError("Max retries reached while trying to receive data");
//           break;
//         }
//         continue;
//       } else {
//         LogError(GetSSLErrorMessage(error));
//         return ERROR;
//       }
//     }
//   }
//   return 0;
// }

uint64_t HttpCore::ReadVarint(std::vector<uint8_t>::iterator &iter,
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

void HttpCore::ParseStreamBuffer(HQUIC Stream,
                                 std::vector<uint8_t> &streamBuffer,
                                 std::string &data) {
  auto iter = streamBuffer.begin();

  while (iter < streamBuffer.end()) {
    // Ensure we have enough data for a frame (frameType + frameLength)
    if (std::distance(iter, streamBuffer.end()) < 3) {
      // std::cout << "Error: Bad frame format (Not enough data)\n";
      break;
    }

    // Read the frame type
    uint64_t frameType = ReadVarint(iter, streamBuffer.end());

    // Read the frame length
    uint64_t frameLength = ReadVarint(iter, streamBuffer.end());

    // Ensure the payload doesn't exceed the bounds of the buffer
    if (std::distance(iter, streamBuffer.end()) < frameLength) {
      std::cout << "Error: Payload exceeds buffer bounds\n";
      break;
    }

    // Handle the frame based on the type
    switch (frameType) {
    case Frame::DATA: // DATA frame
      // std::cout << "[strm][" << Stream << "] Received DATA frame\n";
      // Data might have been transmitted over multiple frames
      data += std::string(iter, iter + frameLength);
      break;

    case Frame::HEADERS:
      // std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

      {
        std::vector<uint8_t> encodedHeaders(iter, iter + frameLength);

        // HttpClient::QPACK_DecodeHeaders(Stream, encodedHeaders);

        DecodeQPACKHeaders(&Stream, encodedHeaders,
                           QuicDecodedHeadersMap[Stream]);

        // headers = std::string(iter, iter + frameLength);
      }

      break;

    default: // Unknown frame type
      std::cout << "[strm][" << Stream << "] Unknown frame type: 0x" << std::hex
                << frameType << std::dec << "\n";
      break;
    }

    iter += frameLength;
  }
  // std::cout << headers << data << "\n";

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < streamBuffer.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << Stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    streamBuffer.end() - iter);
    std::cout << std::endl;
  }
}
