#ifndef FRAMEBUILDER_HPP
#define FRAMEBUILDER_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "common.hpp"
#include "crypto.h"
#include "router.hpp"

class HttpServer;

struct Http2FrameContext {
  const std::vector<uint8_t> &readBuffer;

  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &decodedHeadersMap;

  std::unordered_map<uint32_t, std::vector<uint8_t>> &encodedHeadersMap;

  std::unordered_map<uint32_t, std::string> &dataMap;

  struct lshpack_enc &enc;

  struct lshpack_dec &dec;

  uint32_t &connWindowSize;

  std::unordered_map<uint32_t, uint32_t> &strmWindowSizeMap;

  bool &expectingContFrame;

  // Constructor that accepts references to the original data
  Http2FrameContext(
      const std::vector<uint8_t> &readBuffer,
      std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
          &decodedHeadersMap,
      std::unordered_map<uint32_t, std::vector<uint8_t>> &encodedHeadersMap,
      std::unordered_map<uint32_t, std::string> &dataMap,
      struct lshpack_enc &enc, struct lshpack_dec &dec,
      uint32_t &connWindowSize,
      std::unordered_map<uint32_t, uint32_t> &strmWindowSizeMap,
      bool &expectingContFrame)
      : readBuffer(readBuffer), decodedHeadersMap(decodedHeadersMap),
        encodedHeadersMap(encodedHeadersMap), dataMap(dataMap), enc(enc),
        dec(dec), connWindowSize(connWindowSize),
        strmWindowSizeMap(strmWindowSizeMap),
        expectingContFrame(expectingContFrame) {}
};

class IHttp2FrameHandler {
private:
  virtual int HandleDataFrame(void *context, uint32_t frameStream,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandleHeadersFrame(void *context, uint32_t frameStream,
                                 uint32_t readOffset, uint32_t payloadLength,
                                 uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandlePriorityFrame(void *context, uint32_t frameStream,
                                  uint32_t readOffset, uint32_t payloadLength,
                                  uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandleRstStreamFrame(void *context, uint32_t frameStream,
                                   uint32_t readOffset, uint32_t payloadLength,
                                   uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandleSettingsFrame(void *context, uint32_t frameStream,
                                  uint32_t readOffset, uint32_t payloadLength,
                                  uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandlePingFrame(void *context, uint32_t frameStream,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandleGoAwayFrame(void *context, uint32_t frameStream,
                                uint32_t readOffset, uint32_t payloadLength,
                                uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandleWindowUpdateFrame(void *context, uint32_t frameStream,
                                      uint32_t readOffset,
                                      uint32_t payloadLength,
                                      uint8_t frameFlags, SSL *ssl) = 0;

  virtual int HandleContinuationFrame(void *context, uint32_t frameStream,
                                      uint32_t readOffset,
                                      uint32_t payloadLength,
                                      uint8_t frameFlags, SSL *ssl) = 0;

public:
  // virtual ~IHttp2FrameHandler() = default;
  virtual int ProcessFrame(void *context, uint8_t frameType,
                           uint32_t frameStream, uint32_t readOffset,
                           uint32_t payloadLength, uint8_t frameFlags,
                           SSL *ssl) = 0;
};

class Http2ServerFrameHandler : IHttp2FrameHandler {
private:
  std::weak_ptr<Router> router;

  std::weak_ptr<TcpTransport> transport;

  std::weak_ptr<Http2FrameBuilder> frameBuilder;

  std::weak_ptr<HpackCodec> codec;

  int HandleDataFrame(void *context, uint32_t frameStream, uint32_t readOffset,
                      uint32_t payloadLength, uint8_t frameFlags,
                      SSL *ssl) override;

  int HandleHeadersFrame(void *context, uint32_t frameStream,
                         uint32_t readOffset, uint32_t payloadLength,
                         uint8_t frameFlags, SSL *ssl) override;

  int HandlePriorityFrame(void *context, uint32_t frameStream,
                          uint32_t readOffset, uint32_t payloadLength,
                          uint8_t frameFlags, SSL *ssl) override;

  int HandleRstStreamFrame(void *context, uint32_t frameStream,
                           uint32_t readOffset, uint32_t payloadLength,
                           uint8_t frameFlags, SSL *ssl) override;

  int HandleSettingsFrame(void *context, uint32_t frameStream,
                          uint32_t readOffset, uint32_t payloadLength,
                          uint8_t frameFlags, SSL *ssl) override;

  int HandlePingFrame(void *context, uint32_t frameStream, uint32_t readOffset,
                      uint32_t payloadLength, uint8_t frameFlags,
                      SSL *ssl) override;

  int HandleGoAwayFrame(void *context, uint32_t frameStream,
                        uint32_t readOffset, uint32_t payloadLength,
                        uint8_t frameFlags, SSL *ssl) override;

  int HandleWindowUpdateFrame(void *context, uint32_t frameStream,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl) override;

  int HandleContinuationFrame(void *context, uint32_t frameStream,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl) override;

public:
  explicit Http2ServerFrameHandler(
      const std::shared_ptr<TcpTransport> &tcpTransport,
      const std::shared_ptr<Http2FrameBuilder> &http2FrameBuilder,
      const std::shared_ptr<HpackCodec> &hpackCodec,
      const std::shared_ptr<Router> &router)
      : transport(tcpTransport), frameBuilder(http2FrameBuilder),
        codec(hpackCodec), router(router) {}

  int ProcessFrame(void *context, uint8_t frameType, uint32_t frameStream,
                   uint32_t readOffset, uint32_t payloadLength,
                   uint8_t frameFlags, SSL *ssl) override;
};

class Http2ClientFrameHandler : IHttp2FrameHandler {
private:
  std::weak_ptr<TcpTransport> transport;

  std::weak_ptr<Http2FrameBuilder> frameBuilder;

  std::weak_ptr<HpackCodec> codec;

  int HandleDataFrame(void *context, uint32_t frameStream, uint32_t readOffset,
                      uint32_t payloadLength, uint8_t frameFlags,
                      SSL *ssl) override;

  int HandleHeadersFrame(void *context, uint32_t frameStream,
                         uint32_t readOffset, uint32_t payloadLength,
                         uint8_t frameFlags, SSL *ssl) override;

  int HandlePriorityFrame(void *context, uint32_t frameStream,
                          uint32_t readOffset, uint32_t payloadLength,
                          uint8_t frameFlags, SSL *ssl) override;

  int HandleRstStreamFrame(void *context, uint32_t frameStream,
                           uint32_t readOffset, uint32_t payloadLength,
                           uint8_t frameFlags, SSL *ssl) override;

  int HandleSettingsFrame(void *context, uint32_t frameStream,
                          uint32_t readOffset, uint32_t payloadLength,
                          uint8_t frameFlags, SSL *ssl) override;

  int HandlePingFrame(void *context, uint32_t frameStream, uint32_t readOffset,
                      uint32_t payloadLength, uint8_t frameFlags,
                      SSL *ssl) override;

  int HandleGoAwayFrame(void *context, uint32_t frameStream,
                        uint32_t readOffset, uint32_t payloadLength,
                        uint8_t frameFlags, SSL *ssl) override;

  int HandleWindowUpdateFrame(void *context, uint32_t frameStream,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl) override;

  int HandleContinuationFrame(void *context, uint32_t frameStream,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl) override;

public:
  explicit Http2ClientFrameHandler(
      const std::shared_ptr<TcpTransport> &tcpTransport,
      const std::shared_ptr<Http2FrameBuilder> &http2FrameBuilder,
      const std::shared_ptr<HpackCodec> &hpackCodec)
      : transport(tcpTransport), frameBuilder(http2FrameBuilder),
        codec(hpackCodec) {}

  int ProcessFrame(void *context, uint8_t frameType, uint32_t frameStream,
                   uint32_t readOffset, uint32_t payloadLength,
                   uint8_t frameFlags, SSL *ssl) override;
};

// class Http3FrameHandler {
// public:
//   explicit Http3FrameHandler(HttpServer *server) : serverRouter(server) {}
//
//   void ProcessFrame(void * context, uint32_t frameStream, const
//   std::vector<uint8_t> &buffer, uint32_t readOffset,
//                     uint32_t payloadLength, uint8_t frameFlags,
//                     SSL *ssl) override;
//
// private:
//   int HandleDataFrame(void * context, uint32_t frameStream, const
//   std::vector<uint8_t> &buffer, uint32_t readOffset,
//                        uint32_t payloadLength, uint8_t frameFlags, SSL *ssl);
//   int HandleHeadersFrame(void * context, uint32_t frameStream, const
//   std::vector<uint8_t> &buffer, uint32_t readOffset,
//                           uint32_t payloadLength, uint8_t frameFlags, SSL
//                           *ssl);
//
//   HttpServer *serverRouter; // Reference to the server
// };

#endif // FRAMEBUILDER_HPP
