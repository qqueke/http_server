#include "common.hpp"

#include <iostream>

#include "log.hpp"
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
void HTTPBase::RequestHTTP1ToHTTP3Headers(
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

        // Remove "Connection" header
        if (key != "Connection")
          headersMap[key] = value;
        // headers.emplace_back(key, value);
      }
    }
  }
}

// HTTP1 Response Formatted String to HTTP3 Headers Map
void HTTPBase::ResponseHTTP1ToHTTP3Headers(
    const std::string &http1Headers,
    std::unordered_map<std::string, std::string> &headerMap) {
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
      if (secondSpace != std::string::npos) {
        key = ":status";
        value = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        // headers.emplace_back(key, value);
        headerMap[key] = value;

      } else {
        key = line.substr(0, firstSpace - 1);
        value = line.substr(firstSpace + 1);

        // Remove "Connection" header
        if (key != "Connection")
          headerMap[key] = value;
        // headers.emplace_back(key, value);
      }
    }
  }
}

int HTTPBase::SendFramesToStream(
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

        return -1;
      }
    }
  }
  return 0;
}

int HTTPBase::SendFramesToNewConn(
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

std::vector<uint8_t> HTTPBase::BuildDataFrame(std::string &data) {
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
HTTPBase::BuildHeaderFrame(const std::vector<uint8_t> &encodedHeaders) {
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

void HTTPBase::EncQPACKHeaders(
    std::unordered_map<std::string, std::string> &headersMap,
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

  ret = lsqpack_enc_start_header(enc.data(), 100, 0);

  enum lsqpack_enc_status encStatus;

  std::vector<std::pair<std::vector<unsigned char>, size_t>> encodedHeadersInfo;
  // Iterate through the headersMap and encode each header

  size_t headerSize = 1024;
  size_t totalHeaderSize = 0;
  for (const auto &header : headersMap) {
    // auto header = headersMap.begin();
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
}
