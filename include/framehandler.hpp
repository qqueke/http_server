#ifndef FRAMEBUILDER_HPP
#define FRAMEBUILDER_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto.h"
// #include "server.hpp"

class HttpServer;

struct Http2FrameContext {
  // References to the original data maps
  std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
      &TcpDecodedHeadersMap;
  std::unordered_map<uint32_t, std::vector<uint8_t>> &EncodedHeadersBufferMap;
  std::unordered_map<uint32_t, std::string> &TcpDataMap;

  // References to the HPACK encoder and decoder
  struct lshpack_enc &enc;
  struct lshpack_dec &dec;
  bool &goAway;
  bool &expectingContFrame;

  uint8_t &num;
  // Constructor that accepts references to the original data
  Http2FrameContext(
      std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>>
          &TcpDecodedHeadersMap,
      std::unordered_map<uint32_t, std::vector<uint8_t>>
          &EncodedHeadersBufferMap,
      std::unordered_map<uint32_t, std::string> &TcpDataMap,
      struct lshpack_enc &enc, struct lshpack_dec &dec, uint8_t &num,
      bool &GOAWAY, bool &expectingContFrame)
      : TcpDecodedHeadersMap(TcpDecodedHeadersMap),
        EncodedHeadersBufferMap(EncodedHeadersBufferMap),
        TcpDataMap(TcpDataMap), enc(enc), dec(dec), num(num), goAway(GOAWAY),
        expectingContFrame(expectingContFrame) {}
};

class Http2FrameHandler {
private:
  HttpServer *server;

  int HandleDataFrame(void *context, uint32_t frameStream,
                      const std::vector<uint8_t> &buffer, uint32_t readOffset,
                      uint32_t payloadLength, uint8_t frameFlags, SSL *ssl);

  int HandleHeadersFrame(void *context, uint32_t frameStream,
                         const std::vector<uint8_t> &buffer,
                         uint32_t readOffset, uint32_t payloadLength,
                         uint8_t frameFlags, SSL *ssl);

  int HandlePriorityFrame(void *context, uint32_t frameStream,
                          const std::vector<uint8_t> &buffer,
                          uint32_t readOffset, uint32_t payloadLength,
                          uint8_t frameFlags, SSL *ssl);

  int HandleRstStreamFrame(void *context, uint32_t frameStream,
                           const std::vector<uint8_t> &buffer,
                           uint32_t readOffset, uint32_t payloadLength,
                           uint8_t frameFlags, SSL *ssl);

  int HandleSettingsFrame(void *context, uint32_t frameStream,
                          const std::vector<uint8_t> &buffer,
                          uint32_t readOffset, uint32_t payloadLength,
                          uint8_t frameFlags, SSL *ssl);

  int HandlePingFrame(void *context, uint32_t frameStream,
                      const std::vector<uint8_t> &buffer, uint32_t readOffset,
                      uint32_t payloadLength, uint8_t frameFlags, SSL *ssl);

  int HandleGoAwayFrame(void *context, uint32_t frameStream,
                        const std::vector<uint8_t> &buffer, uint32_t readOffset,
                        uint32_t payloadLength, uint8_t frameFlags, SSL *ssl);

  int HandleWindowUpdateFrame(void *context, uint32_t frameStream,
                              const std::vector<uint8_t> &buffer,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl);

  int HandleContinuationFrame(void *context, uint32_t frameStream,
                              const std::vector<uint8_t> &buffer,
                              uint32_t readOffset, uint32_t payloadLength,
                              uint8_t frameFlags, SSL *ssl);

public:
  explicit Http2FrameHandler(HttpServer *server) : server(server) {}

  int ProcessFrame(void *context, uint8_t frameType, uint32_t frameStream,
                   const std::vector<uint8_t> &buffer, uint32_t readOffset,
                   uint32_t payloadLength, uint8_t frameFlags, SSL *ssl);
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
