#include "common.h"

#include <lshpack.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <thread>

#include "err.h"
#include "http2_frame_builder.h"
#include "log.h"
#include "lsqpack.h"
#include "sstream"
#include "utils.h"

HttpCore::HttpCore() {
  // hpackCodec = std::make_unique<HpackCodec>();
  qpackCodec = std::make_unique<QpackCodec>();

  // http2FrameBuilder = std::make_unique<Http2FrameBuilder>();
  http3FrameBuilder = std::make_unique<Http3FrameBuilder>();

  // tcpTransport = std::make_unique<TcpTransport>();
  quicTransport = std::make_unique<QuicTransport>();
}

void HttpCore::EncodeHPACKHeaders(
    lshpack_enc &encoder,
    const std::unordered_map<std::string, std::string> &headers,
    std::vector<uint8_t> &encoded_headers) {
  hpackCodec->Encode(static_cast<void *>(&encoder), headers, encoded_headers);
}

void HttpCore::DecodeHPACKHeaders(
    lshpack_dec &decoder, std::vector<uint8_t> &encoded_headers,
    std::unordered_map<std::string, std::string> &decodedHeaders) {
  hpackCodec->Decode(static_cast<void *>(&decoder), encoded_headers,
                     decodedHeaders);
}

void HttpCore::EncodeQPACKHeaders(
    HQUIC *stream, const std::unordered_map<std::string, std::string> &headers,
    std::vector<uint8_t> &encoded_headers) {
  qpackCodec->Encode(static_cast<void *>(stream), headers, encoded_headers);
}

void HttpCore::DecodeQPACKHeaders(
    HQUIC *stream, std::vector<uint8_t> &encoded_headers,
    std::unordered_map<std::string, std::string> &decodedHeaders) {
  qpackCodec->Decode(static_cast<void *>(stream), encoded_headers,
                     decodedHeaders);
}

std::vector<uint8_t> HttpCore::BuildHttp2Frame(
    Frame type, uint8_t frame_flags, uint32_t stream_id, uint32_t errorCode,
    uint32_t increment, const std::vector<uint8_t> &encoded_headers,
    const std::string &data) {
  return http2FrameBuilder->BuildFrame(type, frame_flags, stream_id, errorCode,
                                       increment, encoded_headers, data);
}

std::vector<uint8_t> HttpCore::BuildHttp3Frame(
    Frame type, uint32_t stream_id, const std::vector<uint8_t> &encoded_headers,
    const std::string &data) {
  return http3FrameBuilder->BuildFrame(type, stream_id, encoded_headers, data);
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
                      uint32_t write_offset, bool useQuic) {
  if (useQuic) {
    return quicTransport->Read(connection, buffer, write_offset);
  } else {
    return tcpTransport->Read(connection, buffer, write_offset);
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
                         uint32_t write_offset, std::mutex &mut, bool useQuic) {
  if (useQuic) {
    return quicTransport->Read_TS(connection, buffer, write_offset, mut);
  } else {
    return tcpTransport->Read_TS(connection, buffer, write_offset, mut);
  }
}

// HTTP1 Request Formatted String to HTTP3 Headers Map
void HttpCore::ReqHeaderToPseudoHeader(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headers_map) {
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
        headers_map[key] = value;
        // headers.emplace_back(key, value);

        key = ":scheme";
        value = "https";

        headers_map[key] = value;
        // headers.emplace_back(key, value);

        key = ":path";
        value = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);

        headers_map[key] = value;
        // headers.emplace_back(key, value);

      } else {
        key = line.substr(0, firstSpace - 1);
        value = line.substr(firstSpace + 1);
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        // Remove "Connection" header
        if (key != "connection") headers_map[key] = value;
      }
    }
  }
}

// HTTP1 Response Formatted String to HTTP3 Headers Map

void HttpCore::RespHeaderToPseudoHeader(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headers_map) {
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
          headers_map.find(":status") == headers_map.end()) {
        headers_map[":status"] =
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
      //     headers_map[key] = value;
      //   // headers.emplace_back(key, value);
      // }
    }
  }
  //
  // std::cout << "Headers size: " << http1Headers.size()
  //           << " HeadersMap size: " << headers_map.size() << std::endl;
}

// int HttpCore::HTTP1_SendFile(SSL *ssl, const std::string &file_path) {
//   // std::cout << "Sending HTTP1 response" << std::endl;
//
//   size_t totalBytesSent = 0;
//   size_t responseSize = response.size();
//   int retry_count = 0;
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
//         if (retry_count < MAX_RETRIES) {
//           retry_count++;
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
      value >> 6;  // Get the prefix to determine the length of the varint
  size_t length = 1 << prefix;  // 1, 2, 4, or 8 bytes

  value &= 0x3F;  // Mask out the 2 most significant bits

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

void HttpCore::ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &strm_buf,
                                 std::string &data) {
  auto iter = strm_buf.begin();

  while (iter < strm_buf.end()) {
    // Ensure we have enough data for a frame (frame_type + frameLength)
    if (std::distance(iter, strm_buf.end()) < 3) {
      // std::cout << "Error: Bad frame format (Not enough data)\n";
      break;
    }

    // Read the frame type
    uint64_t frame_type = ReadVarint(iter, strm_buf.end());

    // Read the frame length
    uint64_t frameLength = ReadVarint(iter, strm_buf.end());

    // Ensure the payload doesn't exceed the bounds of the buffer
    if (std::distance(iter, strm_buf.end()) < frameLength) {
      std::cout << "Error: Payload exceeds buffer bounds\n";
      break;
    }

    // Handle the frame based on the type
    switch (frame_type) {
      case Frame::DATA:  // DATA frame
        // std::cout << "[strm][" << Stream << "] Received DATA frame\n";
        // Data might have been transmitted over multiple frames
        data += std::string(iter, iter + frameLength);
        break;

      case Frame::HEADERS:
        // std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

        {
          std::vector<uint8_t> encoded_headers(iter, iter + frameLength);

          // HttpClient::QPACK_DecodeHeaders(Stream, encoded_headers);

          DecodeQPACKHeaders(&Stream, encoded_headers,
                             QuicDecodedHeadersMap[Stream]);

          // headers = std::string(iter, iter + frameLength);
        }

        break;

      default:  // Unknown frame type
        std::cout << "[strm][" << Stream << "] Unknown frame type: 0x"
                  << std::hex << frame_type << std::dec << "\n";
        break;
    }

    iter += frameLength;
  }
  // std::cout << headers << data << "\n";

  // Optionally, print any remaining unprocessed data in the buffer
  if (iter < strm_buf.end()) {
    std::cout << "Error: Remaining data for in Buffer from Stream: " << Stream
              << "-------\n";
    std::cout.write(reinterpret_cast<const char *>(&(*iter)),
                    strm_buf.end() - iter);
    std::cout << std::endl;
  }
}
