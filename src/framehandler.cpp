#include "framehandler.hpp"

#include <iostream>

#include "log.hpp"
#include "server.hpp"

static void ValidatePseudoHeadersTmp(
    std::unordered_map<std::string, std::string> &headersMap) {
  static constexpr std::array<std::string_view, 3> requiredHeaders = {
      ":method", ":scheme", ":path"};

  for (const auto &header : requiredHeaders) {
    if (headersMap.find(std::string(header)) == headersMap.end()) {
      // LogError("Failed to validate pseudo-headers (missing header field)");
      headersMap[":method"] = "BR";
      headersMap[":path"] = "";
      return;
    }
  }
}

int Http2ServerFrameHandler::ProcessFrame(void *context, uint8_t frameType,
                                          uint32_t frameStream,
                                          uint32_t readOffset,
                                          uint32_t payloadLength,
                                          uint8_t frameFlags, SSL *ssl) {
  switch (frameType) {
  case Frame::DATA:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] DATA frame\n";
#endif

    return HandleDataFrame(context, frameStream, readOffset, payloadLength,
                           frameFlags, ssl);
  case Frame::HEADERS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] HEADERS frame\n";
#endif

    return HandleHeadersFrame(context, frameStream, readOffset, payloadLength,
                              frameFlags, ssl);
  case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] PRIORITY frame\n";
#endif

    return HandlePriorityFrame(context, frameStream, readOffset, payloadLength,
                               frameFlags, ssl);
  case Frame::RST_STREAM:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] RST_STREAM frame\n";
#endif

    return HandleRstStreamFrame(context, frameStream, readOffset, payloadLength,
                                frameFlags, ssl);
    break;
  case Frame::SETTINGS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] SETTINGS frame\n";
#endif

    return HandleSettingsFrame(context, frameStream, readOffset, payloadLength,
                               frameFlags, ssl);
  case Frame::PING:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] PING frame\n";
#endif

    return HandlePingFrame(context, frameStream, readOffset, payloadLength,
                           frameFlags, ssl);
  case Frame::GOAWAY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] GOAWAY frame\n";
#endif

    return HandleGoAwayFrame(context, frameStream, readOffset, payloadLength,
                             frameFlags, ssl);
  case Frame::CONTINUATION:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] CONTINUATION frame\n";
#endif

    return HandleContinuationFrame(context, frameStream, readOffset,
                                   payloadLength, frameFlags, ssl);
  case Frame::WINDOW_UPDATE:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] WINDOW_UPDATE frame\n";
#endif

    return HandleWindowUpdateFrame(context, frameStream, readOffset,
                                   payloadLength, frameFlags, ssl);
  default:
    LogError("Unknown frame type");
    return ERROR;
  }
}

int Http2ServerFrameHandler::HandleDataFrame(void *context,
                                             uint32_t frameStream,

                                             uint32_t readOffset,
                                             uint32_t payloadLength,
                                             uint8_t frameFlags, SSL *ssl) {
  auto transportPtr = transport.lock();
  if (transportPtr == nullptr) {
    return ERROR;
  }
  auto frameBuilderPtr = frameBuilder.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  auto codecPtr = codec.lock();
  if (codecPtr == nullptr) {
    return ERROR;
  }
  auto routerPtr = router.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  const auto &readBuffer = frameContext.readBuffer;
  auto &TcpDecodedHeadersMap = frameContext.decodedHeadersMap;
  auto &EncodedHeadersBufferMap = frameContext.encodedHeadersMap;
  auto &TcpDataMap = frameContext.dataMap;
  auto &dec = frameContext.dec;
  auto &enc = frameContext.enc;
  auto &connWindowSize = frameContext.connWindowSize;
  auto &strmWindowSizeMap = frameContext.strmWindowSizeMap;

  const uint8_t *framePtr = readBuffer.data() + readOffset;

  TcpDataMap[frameStream] += std::string(
      reinterpret_cast<const char *>(framePtr + FRAME_HEADER_LENGTH),
      payloadLength);

  if (isFlagSet(frameFlags, END_STREAM_FLAG)) {
#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << TcpDataMap[frameStream] << std::endl;
#endif

    ValidatePseudoHeadersTmp(TcpDecodedHeadersMap[frameStream]);

    auto [headers, body] = routerPtr->RouteRequest(
        TcpDecodedHeadersMap[frameStream][":method"],
        TcpDecodedHeadersMap[frameStream][":path"], TcpDataMap[frameStream]);

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> EncodedHeaders(256);
    codecPtr->Encode(static_cast<void *>(&enc), headersMap, EncodedHeaders);

    if (body.empty()) {
      (void)transportPtr->Send(
          ssl, frameBuilderPtr->BuildFrame(Frame::HEADERS, 0, frameStream, 0, 0,
                                           EncodedHeaders));
    } else {
      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);
      frames.emplace_back(frameBuilderPtr->BuildFrame(
          Frame::HEADERS, 0, frameStream, 0, 0, EncodedHeaders));
      frames.emplace_back(frameBuilderPtr->BuildFrame(
          Frame::DATA, 0, frameStream, 0, 0, {}, body));

      (void)transportPtr->SendBatch(ssl, frames);
    }

    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    TcpDataMap.erase(frameStream);
    TcpDecodedHeadersMap.erase(frameStream);
    EncodedHeadersBufferMap.erase(frameStream);
  }
  return 0;
}

int Http2ServerFrameHandler::HandleHeadersFrame(void *context,
                                                uint32_t frameStream,

                                                uint32_t readOffset,
                                                uint32_t payloadLength,
                                                uint8_t frameFlags, SSL *ssl) {
  auto transportPtr = transport.lock();
  if (transportPtr == nullptr) {
    return ERROR;
  }
  auto frameBuilderPtr = frameBuilder.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  auto codecPtr = codec.lock();
  if (codecPtr == nullptr) {
    return ERROR;
  }
  auto routerPtr = router.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  const auto &readBuffer = frameContext.readBuffer;
  auto &TcpDecodedHeadersMap = frameContext.decodedHeadersMap;
  auto &EncodedHeadersBufferMap = frameContext.encodedHeadersMap;
  auto &TcpDataMap = frameContext.dataMap;
  auto &dec = frameContext.dec;
  auto &enc = frameContext.enc;
  auto &connWindowSize = frameContext.connWindowSize;
  auto &strmWindowSizeMap = frameContext.strmWindowSizeMap;

  bool &expectingContFrame = frameContext.expectingContFrame;

  const uint8_t *framePtr = readBuffer.data() + readOffset;

  if (frameStream == 0) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  }

  uint8_t *headerBlockStart =
      const_cast<uint8_t *>(framePtr) + FRAME_HEADER_LENGTH;
  uint8_t *payloadEnd = headerBlockStart + payloadLength;
  uint8_t padLength = 0;

  if (isFlagSet(frameFlags, HTTP2Flags::PADDED_FLAG)) {
    padLength = headerBlockStart[0];
    ++headerBlockStart; // Jump over pad length
  }

  if (isFlagSet(frameFlags, HTTP2Flags::PRIORITY_FLAG)) {
    headerBlockStart += 4; // Jump over stream dependency
    ++headerBlockStart;    // Jump over weight
  }

  uint32_t headerBlockLength = payloadEnd - headerBlockStart - padLength;

  if (headerBlockStart + headerBlockLength > payloadEnd) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::RST_STREAM, 0, frameStream,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  // Do we really need to buffer the header blocks?
  EncodedHeadersBufferMap[frameStream].insert(
      EncodedHeadersBufferMap[frameStream].end(), headerBlockStart,
      headerBlockStart + headerBlockLength);

  if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
      isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    codecPtr->Decode(static_cast<void *>(&dec),
                     EncodedHeadersBufferMap[frameStream],
                     TcpDecodedHeadersMap[frameStream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << TcpDataMap[frameStream] << std::endl;
#endif

    ValidatePseudoHeadersTmp(TcpDecodedHeadersMap[frameStream]);

    auto [headers, body] =
        routerPtr->RouteRequest(TcpDecodedHeadersMap[frameStream][":method"],
                                TcpDecodedHeadersMap[frameStream][":path"]);

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> EncodedHeaders(256);

    codecPtr->Encode(static_cast<void *>(&enc), headersMap, EncodedHeaders);

    if (body == "") {
      (void)transportPtr->Send(
          ssl, frameBuilderPtr->BuildFrame(Frame::HEADERS, 0, frameStream, 0, 0,
                                           EncodedHeaders));
    } else {
      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);
      frames.emplace_back(frameBuilderPtr->BuildFrame(
          Frame::HEADERS, 0, frameStream, 0, 0, EncodedHeaders));

      frames.emplace_back(frameBuilderPtr->BuildFrame(
          Frame::DATA, 0, frameStream, 0, 0, {}, body));

      (void)transportPtr->SendBatch(ssl, frames);
    }

    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    TcpDataMap.erase(frameStream);
    TcpDecodedHeadersMap.erase(frameStream);
    EncodedHeadersBufferMap.erase(frameStream);

    return 0;
  }

  if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    codecPtr->Decode(static_cast<void *>(&dec),
                     EncodedHeadersBufferMap[frameStream],
                     TcpDecodedHeadersMap[frameStream]);
  } else {
    expectingContFrame = true;
  }

  return 0;
}

int Http2ServerFrameHandler::HandlePriorityFrame(void *context,
                                                 uint32_t frameStream,

                                                 uint32_t readOffset,
                                                 uint32_t payloadLength,
                                                 uint8_t frameFlags, SSL *ssl) {
  return 0;
}

int Http2ServerFrameHandler::HandleRstStreamFrame(
    void *context, uint32_t frameStream,

    uint32_t readOffset, uint32_t payloadLength, uint8_t frameFlags, SSL *ssl) {
  auto transportPtr = transport.lock();
  if (transportPtr == nullptr) {
    return ERROR;
  }
  auto frameBuilderPtr = frameBuilder.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  auto codecPtr = codec.lock();
  if (codecPtr == nullptr) {
    return ERROR;
  }
  auto routerPtr = router.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  const auto &readBuffer = frameContext.readBuffer;
  auto &TcpDecodedHeadersMap = frameContext.decodedHeadersMap;
  auto &EncodedHeadersBufferMap = frameContext.encodedHeadersMap;
  auto &TcpDataMap = frameContext.dataMap;

  const uint8_t *framePtr = readBuffer.data() + readOffset;

  if (frameStream == 0) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  } else if (payloadLength != 4) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  uint32_t error = (framePtr[9] << 24) | (framePtr[10] << 16) |
                   (framePtr[11] << 8) | framePtr[12];

  TcpDataMap.erase(frameStream);
  TcpDecodedHeadersMap.erase(frameStream);
  EncodedHeadersBufferMap.erase(frameStream);

  return 0;
}

int Http2ServerFrameHandler::HandleSettingsFrame(void *context,
                                                 uint32_t frameStream,
                                                 uint32_t readOffset,
                                                 uint32_t payloadLength,
                                                 uint8_t frameFlags, SSL *ssl) {
  auto transportPtr = transport.lock();
  if (transportPtr == nullptr) {
    return ERROR;
  }
  auto frameBuilderPtr = frameBuilder.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  auto codecPtr = codec.lock();
  if (codecPtr == nullptr) {
    return ERROR;
  }
  auto routerPtr = router.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  if (payloadLength % 6 != 0) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  } else if (frameStream != 0) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  if (isFlagSet(frameFlags, HTTP2Flags::NONE_FLAG)) {
    // Parse their settings and update this connection settings
    // to be the minimum between ours and theirs

    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::SETTINGS,
                                         HTTP2Flags::SETTINGS_ACK_FLAG));

  } else if (isFlagSet(frameFlags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
    if (payloadLength != 0) {
      (void)transportPtr->Send(
          ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
      return ERROR;
    }
  }

  return 0;
}

int Http2ServerFrameHandler::HandlePingFrame(void *context,
                                             uint32_t frameStream,
                                             uint32_t readOffset,
                                             uint32_t payloadLength,
                                             uint8_t frameFlags, SSL *ssl) {
  auto transportPtr = transport.lock();
  if (transportPtr == nullptr) {
    return ERROR;
  }
  auto frameBuilderPtr = frameBuilder.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  auto codecPtr = codec.lock();
  if (codecPtr == nullptr) {
    return ERROR;
  }
  auto routerPtr = router.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  if (frameStream != 0) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  } else if (payloadLength != 8) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  if (!isFlagSet(frameFlags, HTTP2Flags::PING_ACK_FLAG)) {
    // {
    //   if (frame.size() != FRAME_HEADER_LENGTH + payloadLength) {
    //     frame.resize(FRAME_HEADER_LENGTH + payloadLength);
    //   }
    //
    //   memcpy(frame.data(), framePtr, FRAME_HEADER_LENGTH +
    //   payloadLength); frame[4] = HTTP2Flags::PING_ACK_FLAG;
    //
    //   Send(ssl, frame);
    // }
  }

  return 0;
}

int Http2ServerFrameHandler::HandleGoAwayFrame(void *context,
                                               uint32_t frameStream,
                                               uint32_t readOffset,
                                               uint32_t payloadLength,
                                               uint8_t frameFlags, SSL *ssl) {
  return 0;
}

int Http2ServerFrameHandler::HandleContinuationFrame(
    void *context, uint32_t frameStream, uint32_t readOffset,
    uint32_t payloadLength, uint8_t frameFlags, SSL *ssl) {
  auto transportPtr = transport.lock();
  if (transportPtr == nullptr) {
    return ERROR;
  }
  auto frameBuilderPtr = frameBuilder.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  auto codecPtr = codec.lock();
  if (codecPtr == nullptr) {
    return ERROR;
  }
  auto routerPtr = router.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }

  if (frameStream == 0) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  }

  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  const auto &readBuffer = frameContext.readBuffer;
  auto &TcpDecodedHeadersMap = frameContext.decodedHeadersMap;
  auto &EncodedHeadersBufferMap = frameContext.encodedHeadersMap;
  auto &TcpDataMap = frameContext.dataMap;
  auto &dec = frameContext.dec;
  auto &enc = frameContext.enc;
  auto &connWindowSize = frameContext.connWindowSize;
  auto &strmWindowSizeMap = frameContext.strmWindowSizeMap;

  bool &expectingContFrame = frameContext.expectingContFrame;

  const uint8_t *framePtr = readBuffer.data() + readOffset;

  EncodedHeadersBufferMap[frameStream].insert(
      EncodedHeadersBufferMap[frameStream].end(),
      framePtr + FRAME_HEADER_LENGTH,
      framePtr + FRAME_HEADER_LENGTH + payloadLength);

  if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
      isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    expectingContFrame = false;

    codecPtr->Decode(static_cast<void *>(&dec),
                     EncodedHeadersBufferMap[frameStream],
                     TcpDecodedHeadersMap[frameStream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
      std::cout << key << ": " << value << "\n";
    }
#endif

    ValidatePseudoHeadersTmp(TcpDecodedHeadersMap[frameStream]);

    auto [headers, body] =
        routerPtr->RouteRequest(TcpDecodedHeadersMap[frameStream][":method"],
                                TcpDecodedHeadersMap[frameStream][":path"]);

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> EncodedHeaders(256);

    codecPtr->Encode(static_cast<void *>(&enc), headersMap, EncodedHeaders);

    if (body == "") {
      (void)transportPtr->Send(
          ssl, frameBuilderPtr->BuildFrame(Frame::HEADERS, 0, frameStream, 0, 0,
                                           EncodedHeaders));

    } else {
      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);
      frames.emplace_back(frameBuilderPtr->BuildFrame(
          Frame::HEADERS, 0, frameStream, 0, 0, EncodedHeaders));

      frames.emplace_back(frameBuilderPtr->BuildFrame(
          Frame::DATA, 0, frameStream, 0, 0, {}, body));

      (void)transportPtr->SendBatch(ssl, frames);
    }

    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    TcpDataMap.erase(frameStream);
    TcpDecodedHeadersMap.erase(frameStream);
    EncodedHeadersBufferMap.erase(frameStream);
    return 0;
  }

  if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    expectingContFrame = false;
    codecPtr->Decode(static_cast<void *>(&dec),
                     EncodedHeadersBufferMap[frameStream],
                     TcpDecodedHeadersMap[frameStream]);

  }
  // Expecting another continuation frame ...
  else {
    expectingContFrame = true;
  }

  return 0;
}

int Http2ServerFrameHandler::HandleWindowUpdateFrame(
    void *context, uint32_t frameStream, uint32_t readOffset,
    uint32_t payloadLength, uint8_t frameFlags, SSL *ssl) {
  auto transportPtr = transport.lock();
  if (transportPtr == nullptr) {
    return ERROR;
  }
  auto frameBuilderPtr = frameBuilder.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }
  auto codecPtr = codec.lock();
  if (codecPtr == nullptr) {
    return ERROR;
  }
  auto routerPtr = router.lock();
  if (frameBuilderPtr == nullptr) {
    return ERROR;
  }

  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  const auto &readBuffer = frameContext.readBuffer;

  const uint8_t *framePtr = readBuffer.data() + readOffset;

  uint32_t windowIncrement = (framePtr[9] << 24) | (framePtr[10] << 16) |
                             (framePtr[11] << 8) | framePtr[12];

  // std::cout << "Window increment: " << windowIncrement << "\n";
  if (windowIncrement == 0) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  } else if (payloadLength != 4) {
    (void)transportPtr->Send(
        ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }
  // Re implement when we pass window sizes in context
  if (frameStream == 0) {
    auto &connWindowSize = frameContext.connWindowSize;
    connWindowSize += windowIncrement;
    if (connWindowSize > MAX_FLOW_WINDOW_SIZE) {
      (void)transportPtr->Send(
          ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FLOW_CONTROL_ERROR));
      return ERROR;
    }
  } else {
    auto &strmWindowSizeMap = frameContext.strmWindowSizeMap;
    strmWindowSizeMap[frameStream] += windowIncrement;
    if (strmWindowSizeMap[frameStream] > MAX_FLOW_WINDOW_SIZE) {
      (void)transportPtr->Send(
          ssl, frameBuilderPtr->BuildFrame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FLOW_CONTROL_ERROR));
      return ERROR;
    }
  }
  return 0;
}
