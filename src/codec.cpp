#include "codec.hpp"

#include <iostream>
#include <ostream>

#include "log.hpp"
#include "lshpack.h"
#include "utils.hpp"

void HpackCodec::Encode(
    void *context,
    const std::unordered_map<std::string, std::string> &headersMap,
    std::vector<uint8_t> &encodedHeaders) {
  lshpack_enc *encoder = (lshpack_enc *)context;

  unsigned char *dst = encodedHeaders.data();
  unsigned char *end = dst + encodedHeaders.size();

  char headerBuffer[128];

  struct lsxpack_header headerFormat;

  if (headersMap.find(":status") != headersMap.end()) {
    const std::string &name = ":status";
    const std::string &value = headersMap.at(":status");

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

    dst = lshpack_enc_encode(encoder, dst, end, &headerFormat);
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

    dst = lshpack_enc_encode(encoder, dst, end, &headerFormat);
  }

  encodedHeaders.resize(dst - encodedHeaders.data());
}

void HpackCodec::Decode(
    void *context, std::vector<uint8_t> &encodedHeaders,
    std::unordered_map<std::string, std::string> &decodedHeadersMap) {
  lshpack_dec *decoder = (lshpack_dec *)context;

  const unsigned char *src = const_cast<unsigned char *>(encodedHeaders.data());
  const unsigned char *end = src + encodedHeaders.size();

  struct lsxpack_header headerFormat{};

  char headerBuffer[2048] = {};

  while (src < end) {
    lsxpack_header_prepare_decode(&headerFormat, &headerBuffer[0], 0,
                                  sizeof(headerBuffer));

    int ret = lshpack_dec_decode(decoder, &src, end, &headerFormat);
    if (ret < 0) {
      std::cout << "Failed to decode HPACK headers" << std::endl;
      break;
    }

    // int decodedSize = headerFormat.name_len + headerFormat.val_len +
    //                   lshpack_dec_extra_bytes(dec);

    decodedHeadersMap.emplace(
        std::string(headerFormat.buf + headerFormat.name_offset,
                    headerFormat.name_len),
        std::string(headerFormat.buf + headerFormat.val_offset,
                    headerFormat.val_len));
  }

  // return decodedSize;
}

void QpackCodec::Encode(
    void *context,
    const std::unordered_map<std::string, std::string> &headersMap,
    std::vector<uint8_t> &encodedHeaders) {
  HQUIC *stream = (HQUIC *)context;

  struct lsqpack_enc enc;

  size_t stdcBufSize = 1024;

  std::vector<unsigned char> sdtcBuf(1024);

  lsqpack_enc_opts encOpts{};

  int ret =
      lsqpack_enc_init(&enc, NULL, 0x1000, 0x1000, 0, LSQPACK_ENC_OPT_SERVER,
                       sdtcBuf.data(), &stdcBufSize);

  if (ret != 0) {
    std::cerr << "Error initializing encoder." << std::endl;
    return;
  }

  uint64_t streamId{};
  uint32_t len = (uint32_t)sizeof(streamId);
  if (QUIC_FAILED(
          MsQuic->GetParam(*stream, QUIC_PARAM_STREAM_ID, &len, &streamId))) {
    LogError("Failed to acquire stream id");
  }

  ret = lsqpack_enc_start_header(&enc, streamId, 0);

  enum lsqpack_enc_status encStatus;

  std::vector<std::pair<std::vector<unsigned char>, size_t>> encodedHeadersInfo;
  // Iterate through the headersMap and encode each header

  size_t headerSize = 1024;
  size_t totalHeaderSize = 0;

  // Status needs to be sent first (curl HTTP2 seems to not work otherwise)
  if (headersMap.find(":status") != headersMap.end()) {
    const std::string &name = ":status";
    const std::string &value = headersMap.at(":status");

    std::string combinedHeader = name + ": " + value;

    struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, combinedHeader.c_str(), 0,
                               name.length(), name.length() + 2, value.size());

    size_t encSize = 1024;
    std::vector<unsigned char> encBuf(encSize);

    lsqpack_enc_flags enc_flags{};

    encodedHeadersInfo.emplace_back(std::vector<unsigned char>(headerSize),
                                    headerSize);

    encStatus = lsqpack_enc_encode(
        &enc, encBuf.data(), &encSize, encodedHeadersInfo.back().first.data(),
        &encodedHeadersInfo.back().second, &headerFormat, enc_flags);

    totalHeaderSize += encodedHeadersInfo.back().second;
  }

  for (const auto &header : headersMap) {
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

    encStatus = lsqpack_enc_encode(
        &enc, encBuf.data(), &encSize, encodedHeadersInfo.back().first.data(),
        &encodedHeadersInfo.back().second, &headerFormat, enc_flags);

    totalHeaderSize += encodedHeadersInfo.back().second;
  }

  std::vector<unsigned char> endHeaderBuf(headerSize);

  size_t endHeaderSize =
      lsqpack_enc_end_header(&enc, endHeaderBuf.data(), headerSize, NULL);

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

  lsqpack_enc_cleanup(&enc);
}

static void Dhi_Unblocked(void *hblock_ctx) {}

static struct lsxpack_header *Dhi_PrepareDecode(void *hblock_ctx_p,
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

static int Dhi_ProcessHeader(void *hblock_ctx, struct lsxpack_header *xhdr) {
  std::string headerKey(xhdr->buf + xhdr->name_offset, xhdr->name_len);
  std::string headerValue(xhdr->buf + xhdr->val_offset, xhdr->val_len);

  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx;
  std::unordered_map<std::string, std::string> &headersMap =
      *(block_ctx->decodedHeadersMap);

  headersMap[headerKey] = headerValue;

  return 0;
}

void QpackCodec::Decode(
    void *context, std::vector<uint8_t> &encodedHeaders,
    std::unordered_map<std::string, std::string> &decodedHeaders) {
  HQUIC *stream = (HQUIC *)context;

  std::vector<struct lsqpack_dec> dec(1);

  uint64_t streamId{};
  uint32_t len = (uint32_t)sizeof(streamId);
  if (QUIC_FAILED(
          MsQuic->GetParam(*stream, QUIC_PARAM_STREAM_ID, &len, &streamId))) {
    LogError("Failed to acquire stream id");
  }

  struct lsqpack_dec_hset_if hset_if;
  hset_if.dhi_unblocked = Dhi_Unblocked;
  hset_if.dhi_prepare_decode = Dhi_PrepareDecode;
  hset_if.dhi_process_header = Dhi_ProcessHeader;

  enum lsqpack_dec_opts dec_opts {};
  lsqpack_dec_init(dec.data(), NULL, 0x1000, 0, &hset_if, dec_opts);

  // hblock_ctx_t *blockCtx = (hblock_ctx_t *)malloc(sizeof(hblock_ctx_t));

  std::vector<hblock_ctx_t> blockCtx(1);
  // hblock_ctx_t blockCtx;
  memset(&blockCtx.back(), 0, sizeof(hblock_ctx_t));
  blockCtx.back().decodedHeadersMap = &decodedHeaders;

  const unsigned char *encodedHeadersPtr = encodedHeaders.data();
  size_t totalHeaderSize = encodedHeaders.size();

  enum lsqpack_read_header_status readStatus;

  readStatus = lsqpack_dec_header_in(dec.data(), &blockCtx.back(), streamId,
                                     totalHeaderSize, &encodedHeadersPtr,
                                     totalHeaderSize, NULL, NULL);

  lsqpack_dec_cleanup(dec.data());
}
