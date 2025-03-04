#include "framehandler.hpp"

#include <iostream>

#include "log.hpp"
#include "server.hpp"

int Http2FrameHandler::ProcessFrame(void *context, uint8_t frameType,
                                    uint32_t frameStream,
                                    const std::vector<uint8_t> &buffer,
                                    uint32_t readOffset, uint32_t payloadLength,
                                    uint8_t frameFlags, SSL *ssl) {
  switch (frameType) {
  case Frame::DATA:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] DATA frame\n";
#endif

    return HandleDataFrame(context, frameStream, buffer, readOffset,
                           payloadLength, frameFlags, ssl);
    break;
  case Frame::HEADERS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] HEADERS frame\n";
#endif

    return HandleHeadersFrame(context, frameStream, buffer, readOffset,
                              payloadLength, frameFlags, ssl);
    break;
  case Frame::PRIORITY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] PRIORITY frame\n";
#endif

    return HandlePriorityFrame(context, frameStream, buffer, readOffset,
                               payloadLength, frameFlags, ssl);
    break;
  case Frame::RST_STREAM:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] RST_STREAM frame\n";
#endif

    return HandleRstStreamFrame(context, frameStream, buffer, readOffset,
                                payloadLength, frameFlags, ssl);
    break;
  case Frame::SETTINGS:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] SETTINGS frame\n";
#endif

    return HandleSettingsFrame(context, frameStream, buffer, readOffset,
                               payloadLength, frameFlags, ssl);
    break;
  case Frame::PING:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] PING frame\n";
#endif

    return HandlePingFrame(context, frameStream, buffer, readOffset,
                           payloadLength, frameFlags, ssl);
    break;
  case Frame::GOAWAY:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] GOAWAY frame\n";
#endif

    return HandleGoAwayFrame(context, frameStream, buffer, readOffset,
                             payloadLength, frameFlags, ssl);
    break;
  case Frame::CONTINUATION:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] CONTINUATION frame\n";
#endif

    return HandleContinuationFrame(context, frameStream, buffer, readOffset,
                                   payloadLength, frameFlags, ssl);
    break;
  case Frame::WINDOW_UPDATE:
#ifdef HTTP2_DEBUG
    std::cout << "[strm][" << frameStream << "] WINDOW_UPDATE frame\n";
#endif

    return HandleWindowUpdateFrame(context, frameStream, buffer, readOffset,
                                   payloadLength, frameFlags, ssl);
  default:
    LogError("Unknown frame type");
    return ERROR;
    break;
  }
  return ERROR;
}

int Http2FrameHandler::HandleDataFrame(void *context, uint32_t frameStream,
                                       const std::vector<uint8_t> &buffer,
                                       uint32_t readOffset,
                                       uint32_t payloadLength,
                                       uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &TcpDecodedHeadersMap = frameContext.TcpDecodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> &EncodedHeadersBufferMap =
      frameContext.EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> &TcpDataMap =
      frameContext.TcpDataMap;

  struct lshpack_dec &dec = frameContext.dec;

  struct lshpack_enc &enc = frameContext.enc;

  const uint8_t *framePtr = buffer.data() + readOffset;

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

    server->ValidatePseudoHeaders(TcpDecodedHeadersMap[frameStream]);

    auto [headers, body] = server->router->RouteRequest(
        TcpDecodedHeadersMap[frameStream][":method"],
        TcpDecodedHeadersMap[frameStream][":path"], TcpDataMap[frameStream]);

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> encodedHeaders(256);
    server->EncodeHPACKHeaders(enc, headersMap, encodedHeaders);

    if (body.empty()) {
      server->Send(ssl, server->BuildHttp2Frame(Frame::HEADERS, 0, frameStream,
                                                0, 0, encodedHeaders));
    } else {
      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);
      frames.emplace_back(server->BuildHttp2Frame(
          Frame::HEADERS, 0, frameStream, 0, 0, encodedHeaders));
      frames.emplace_back(
          server->BuildHttp2Frame(Frame::DATA, 0, frameStream, 0, 0, {}, body));

      server->SendBatch(ssl, frames);
    }

    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    TcpDataMap.erase(frameStream);
    TcpDecodedHeadersMap.erase(frameStream);
    EncodedHeadersBufferMap.erase(frameStream);
  }
  return 0;
}

int Http2FrameHandler::HandleHeadersFrame(void *context, uint32_t frameStream,
                                          const std::vector<uint8_t> &buffer,
                                          uint32_t readOffset,
                                          uint32_t payloadLength,
                                          uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &TcpDecodedHeadersMap = frameContext.TcpDecodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> &EncodedHeadersBufferMap =
      frameContext.EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> &TcpDataMap =
      frameContext.TcpDataMap;

  struct lshpack_dec &dec = frameContext.dec;

  struct lshpack_enc &enc = frameContext.enc;

  bool &goAway = frameContext.goAway;
  bool &expectingContFrame = frameContext.expectingContFrame;

  const uint8_t *framePtr = buffer.data() + readOffset;

  if (frameStream == 0) {
    goAway = true;
    server->Send(ssl, server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
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
    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::RST_STREAM, 0, frameStream,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  // Do we really need to buffer the header blocks?
  EncodedHeadersBufferMap[frameStream].insert(
      EncodedHeadersBufferMap[frameStream].end(), headerBlockStart,
      headerBlockStart + headerBlockLength);

  if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
      isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    server->DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
      std::cout << key << ": " << value << "\n";
    }
    std::cout << TcpDataMap[frameStream] << std::endl;
#endif

    server->ValidatePseudoHeaders(TcpDecodedHeadersMap[frameStream]);

    auto [headers, body] = server->router->RouteRequest(
        TcpDecodedHeadersMap[frameStream][":method"],
        TcpDecodedHeadersMap[frameStream][":path"]);

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> encodedHeaders(256);

    server->EncodeHPACKHeaders(enc, headersMap, encodedHeaders);

    if (body == "") {
      server->Send(ssl, server->BuildHttp2Frame(Frame::HEADERS, 0, frameStream,
                                                0, 0, encodedHeaders));
    } else {
      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);
      frames.emplace_back(server->BuildHttp2Frame(
          Frame::HEADERS, 0, frameStream, 0, 0, encodedHeaders));

      frames.emplace_back(
          server->BuildHttp2Frame(Frame::DATA, 0, frameStream, 0, 0, {}, body));

      server->SendBatch(ssl, frames);
    }

    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    TcpDataMap.erase(frameStream);
    TcpDecodedHeadersMap.erase(frameStream);
    EncodedHeadersBufferMap.erase(frameStream);

    return 0;
  }

  if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    server->DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);
  } else {
    expectingContFrame = true;
  }

  return 0;
}

int Http2FrameHandler::HandlePriorityFrame(void *context, uint32_t frameStream,
                                           const std::vector<uint8_t> &buffer,
                                           uint32_t readOffset,
                                           uint32_t payloadLength,
                                           uint8_t frameFlags, SSL *ssl) {
  return 0;
}

int Http2FrameHandler::HandleRstStreamFrame(void *context, uint32_t frameStream,
                                            const std::vector<uint8_t> &buffer,
                                            uint32_t readOffset,
                                            uint32_t payloadLength,
                                            uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &TcpDecodedHeadersMap = frameContext.TcpDecodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> &EncodedHeadersBufferMap =
      frameContext.EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> &TcpDataMap =
      frameContext.TcpDataMap;

  struct lshpack_dec &dec = frameContext.dec;

  struct lshpack_enc &enc = frameContext.enc;

  bool &goAway = frameContext.goAway;
  bool &expectingContFrame = frameContext.expectingContFrame;

  const uint8_t *framePtr = buffer.data() + readOffset;

  if (frameStream == 0) {
    goAway = true;
    server->Send(ssl, server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                              HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  } else if (payloadLength != 4) {
    goAway = true;
    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  {
    uint32_t error = (framePtr[9] << 24) | (framePtr[10] << 16) |
                     (framePtr[11] << 8) | framePtr[12];
  }

  TcpDataMap.erase(frameStream);
  TcpDecodedHeadersMap.erase(frameStream);
  EncodedHeadersBufferMap.erase(frameStream);

  return 0;
}

int Http2FrameHandler::HandleSettingsFrame(void *context, uint32_t frameStream,
                                           const std::vector<uint8_t> &buffer,
                                           uint32_t readOffset,
                                           uint32_t payloadLength,
                                           uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  bool &goAway = frameContext.goAway;

  if (payloadLength % 6 != 0) {
    goAway = true;
    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  } else if (frameStream != 0) {
    goAway = true;
    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  if (isFlagSet(frameFlags, HTTP2Flags::NONE_FLAG)) {
    // Parse their settings and update this connection settings
    // to be the minimum between ours and theirs

    server->Send(ssl, server->BuildHttp2Frame(Frame::SETTINGS,
                                              HTTP2Flags::SETTINGS_ACK_FLAG));

  } else if (isFlagSet(frameFlags, HTTP2Flags::SETTINGS_ACK_FLAG)) {
    if (payloadLength != 0) {
      goAway = true;

      server->Send(ssl,
                   server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                           HTTP2ErrorCode::FRAME_SIZE_ERROR));
      return ERROR;
    }
  }

  return 0;
}

int Http2FrameHandler::HandlePingFrame(void *context, uint32_t frameStream,
                                       const std::vector<uint8_t> &buffer,
                                       uint32_t readOffset,
                                       uint32_t payloadLength,
                                       uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  bool &goAway = frameContext.goAway;

  if (frameStream != 0) {
    goAway = true;
    server->Send(ssl, server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                              HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  } else if (payloadLength != 8) {
    goAway = true;
    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
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

int Http2FrameHandler::HandleGoAwayFrame(void *context, uint32_t frameStream,
                                         const std::vector<uint8_t> &buffer,
                                         uint32_t readOffset,
                                         uint32_t payloadLength,
                                         uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  bool &goAway = frameContext.goAway;
  goAway = true;

  return 0;
}

int Http2FrameHandler::HandleContinuationFrame(
    void *context, uint32_t frameStream, const std::vector<uint8_t> &buffer,
    uint32_t readOffset, uint32_t payloadLength, uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &TcpDecodedHeadersMap = frameContext.TcpDecodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> &EncodedHeadersBufferMap =
      frameContext.EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> &TcpDataMap =
      frameContext.TcpDataMap;

  struct lshpack_dec &dec = frameContext.dec;

  struct lshpack_enc &enc = frameContext.enc;

  bool &goAway = frameContext.goAway;
  bool &expectingContFrame = frameContext.expectingContFrame;

  const uint8_t *framePtr = buffer.data() + readOffset;
  if (frameStream == 0) {
    goAway = true;
    server->Send(ssl, server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                              HTTP2ErrorCode::PROTOCOL_ERROR));
    return ERROR;
  }

  EncodedHeadersBufferMap[frameStream].insert(
      EncodedHeadersBufferMap[frameStream].end(),
      framePtr + FRAME_HEADER_LENGTH,
      framePtr + FRAME_HEADER_LENGTH + payloadLength);

  if (isFlagSet(frameFlags, END_STREAM_FLAG) &&
      isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    expectingContFrame = false;

    server->DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);

#ifdef ECHO
    std::cout << "HTTP2 Request: \n";
    for (auto &[key, value] : TcpDecodedHeadersMap[frameStream]) {
      std::cout << key << ": " << value << "\n";
    }
#endif

    server->ValidatePseudoHeaders(TcpDecodedHeadersMap[frameStream]);

    auto [headers, body] = server->router->RouteRequest(
        TcpDecodedHeadersMap[frameStream][":method"],
        TcpDecodedHeadersMap[frameStream][":path"]);

    std::unordered_map<std::string, std::string> headersMap;
    headersMap.reserve(2);

    HttpCore::RespHeaderToPseudoHeader(headers, headersMap);
    headersMap["alt-svc"] = "h3=\":4567\"; ma=86400";

    std::vector<uint8_t> encodedHeaders(256);

    server->EncodeHPACKHeaders(enc, headersMap, encodedHeaders);

    if (body == "") {
      server->Send(ssl, server->BuildHttp2Frame(Frame::HEADERS, 0, frameStream,
                                                0, 0, encodedHeaders));

    } else {
      std::vector<std::vector<uint8_t>> frames;
      frames.reserve(2);
      frames.emplace_back(server->BuildHttp2Frame(
          Frame::HEADERS, 0, frameStream, 0, 0, encodedHeaders));

      frames.emplace_back(
          server->BuildHttp2Frame(Frame::DATA, 0, frameStream, 0, 0, {}, body));

      server->SendBatch(ssl, frames);
    }

    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::WINDOW_UPDATE, 0, 0, 0, 65536));

    TcpDataMap.erase(frameStream);
    TcpDecodedHeadersMap.erase(frameStream);
    EncodedHeadersBufferMap.erase(frameStream);
    return 0;
  }

  if (isFlagSet(frameFlags, END_HEADERS_FLAG)) {
    expectingContFrame = false;
    server->DecodeHPACKHeaders(dec, EncodedHeadersBufferMap[frameStream],
                               TcpDecodedHeadersMap[frameStream]);

  }
  // Expecting another continuation frame ...
  else {
    expectingContFrame = true;
  }

  return 0;
}

int Http2FrameHandler::HandleWindowUpdateFrame(
    void *context, uint32_t frameStream, const std::vector<uint8_t> &buffer,
    uint32_t readOffset, uint32_t payloadLength, uint8_t frameFlags, SSL *ssl) {
  Http2FrameContext &frameContext =
      *reinterpret_cast<Http2FrameContext *>(context);

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &TcpDecodedHeadersMap = frameContext.TcpDecodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> &EncodedHeadersBufferMap =
      frameContext.EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> &TcpDataMap =
      frameContext.TcpDataMap;

  struct lshpack_dec &dec = frameContext.dec;

  struct lshpack_enc &enc = frameContext.enc;

  bool &goAway = frameContext.goAway;
  bool &expectingContFrame = frameContext.expectingContFrame;

  const uint8_t *framePtr = buffer.data() + readOffset;

  uint32_t windowIncrement = (framePtr[9] << 24) | (framePtr[10] << 16) |
                             (framePtr[11] << 8) | framePtr[12];

  // std::cout << "Window increment: " << windowIncrement << "\n";
  if (windowIncrement == 0) {
    goAway = true;
    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  } else if (payloadLength != 4) {
    goAway = true;
    server->Send(ssl,
                 server->BuildHttp2Frame(Frame::GOAWAY, 0, 0,
                                         HTTP2ErrorCode::FRAME_SIZE_ERROR));
    return ERROR;
  }

  // Re implement when we pass window sizes in context
  // if (frameStream == 0) {
  //   connectionWindowSize += windowIncrement;
  //   if (connectionWindowSize > MAX_FLOW_WINDOW_SIZE) {
  //     goAway = true;
  //
  //     Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
  //                               HTTP2ErrorCode::FLOW_CONTROL_ERROR));
  //     return ERROR;
  //   }
  // } else {
  //   streamWindowSizeMap[frameStream] += windowIncrement;
  //   if (streamWindowSizeMap[frameStream] > MAX_FLOW_WINDOW_SIZE) {
  //     Send(ssl, BuildHttp2Frame(Frame::GOAWAY, 0, 0,
  //                               HTTP2ErrorCode::FLOW_CONTROL_ERROR));
  //     return ERROR;
  //   }
  // }
  return 0;
}
