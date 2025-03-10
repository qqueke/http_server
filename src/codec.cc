#include "../include/codec.h"

#include <iostream>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/log.h"
#include "../include/utils.h"
#include "../lib/ls-hpack/lshpack.h"

void HpackCodec::Encode(
    void *context,
    const std::unordered_map<std::string, std::string> &headers_map,
    std::vector<uint8_t> &encoded_headers) {
  lshpack_enc *encoder = reinterpret_cast<lshpack_enc *>(context);

  unsigned char *dst = encoded_headers.data();
  unsigned char *end = dst + encoded_headers.size();

  char headerBuffer[128];

  struct lsxpack_header headerFormat;

  if (headers_map.find(":status") != headers_map.end()) {
    const std::string &name = ":status";
    const std::string &value = headers_map.at(":status");

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

  for (const auto &header : headers_map) {
    if (header.first == ":status") {
      continue;
    }

    // auto header = headers_map.begin();
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

  encoded_headers.resize(dst - encoded_headers.data());
}

void HpackCodec::Decode(
    void *context, std::vector<uint8_t> &encoded_headers,
    std::unordered_map<std::string, std::string> &decoded_headers_map) {
  lshpack_dec *decoder = reinterpret_cast<lshpack_dec *>(context);

  const unsigned char *src =
      const_cast<unsigned char *>(encoded_headers.data());
  const unsigned char *end = src + encoded_headers.size();

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

    decoded_headers_map.emplace(
        std::string(headerFormat.buf + headerFormat.name_offset,
                    headerFormat.name_len),
        std::string(headerFormat.buf + headerFormat.val_offset,
                    headerFormat.val_len));
  }

  // return decodedSize;
}

void QpackCodec::Encode(
    void *context,
    const std::unordered_map<std::string, std::string> &headers_map,
    std::vector<uint8_t> &encoded_headers) {
  HQUIC *stream = reinterpret_cast<HQUIC *>(context);

  struct lsqpack_enc enc;

  size_t stdcBufSize = 1024;

  std::vector<unsigned char> sdtcBuf(1024);

  lsqpack_enc_opts encOpts{};

  int ret =
      lsqpack_enc_init(&enc, nullptr, 0x1000, 0x1000, 0, LSQPACK_ENC_OPT_SERVER,
                       sdtcBuf.data(), &stdcBufSize);

  if (ret != 0) {
    std::cerr << "Error initializing encoder.\n";
    return;
  }

  uint64_t stream_id{};
  uint32_t len = static_cast<uint32_t>(sizeof(stream_id));
  if (QUIC_FAILED(ms_quic_->GetParam(*stream, QUIC_PARAM_STREAM_ID, &len,
                                     &stream_id))) {
    LogError("Failed to acquire stream id");
  }

  ret = lsqpack_enc_start_header(&enc, stream_id, 0);

  enum lsqpack_enc_status encStatus;

  std::vector<std::pair<std::vector<unsigned char>, size_t>>
      encoded_headersInfo;
  // Iterate through the headers_map and encode each header

  size_t headerSize = 1024;
  size_t totalHeaderSize = 0;

  // Status needs to be sent first (curl HTTP2 seems to not work otherwise)
  if (headers_map.find(":status") != headers_map.end()) {
    const std::string &name = ":status";
    const std::string &value = headers_map.at(":status");

    std::string combinedHeader = name + ": " + value;

    struct lsxpack_header headerFormat;
    lsxpack_header_set_offset2(&headerFormat, combinedHeader.c_str(), 0,
                               name.length(), name.length() + 2, value.size());

    size_t encSize = 1024;
    std::vector<unsigned char> encBuf(encSize);

    lsqpack_enc_flags enc_flags{};

    encoded_headersInfo.emplace_back(std::vector<unsigned char>(headerSize),
                                     headerSize);

    encStatus = lsqpack_enc_encode(
        &enc, encBuf.data(), &encSize, encoded_headersInfo.back().first.data(),
        &encoded_headersInfo.back().second, &headerFormat, enc_flags);

    totalHeaderSize += encoded_headersInfo.back().second;
  }

  for (const auto &header : headers_map) {
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

    encoded_headersInfo.emplace_back(std::vector<unsigned char>(headerSize),
                                     headerSize);

    encStatus = lsqpack_enc_encode(
        &enc, encBuf.data(), &encSize, encoded_headersInfo.back().first.data(),
        &encoded_headersInfo.back().second, &headerFormat, enc_flags);

    totalHeaderSize += encoded_headersInfo.back().second;
  }

  std::vector<unsigned char> endHeaderBuf(headerSize);

  size_t endHeaderSize =
      lsqpack_enc_end_header(&enc, endHeaderBuf.data(), headerSize, NULL);

  totalHeaderSize += endHeaderSize;

  encoded_headers.resize(totalHeaderSize);
  const unsigned char *encoded_headersPtr = encoded_headers.data();

  memcpy(encoded_headers.data(), endHeaderBuf.data(), endHeaderSize);

  totalHeaderSize = endHeaderSize;
  for (auto &headerInfo : encoded_headersInfo) {
    unsigned char *headerPointer = headerInfo.first.data();
    size_t currHeaderSize = headerInfo.second;
    memcpy(encoded_headers.data() + totalHeaderSize, headerPointer,
           currHeaderSize);
    totalHeaderSize += currHeaderSize;
  }

  lsqpack_enc_cleanup(&enc);
}

static void Dhi_Unblocked(void *hblock_ctx) {}

static struct lsxpack_header *Dhi_PrepareDecode(void *hblock_ctx_p,
                                                struct lsxpack_header *xhdr,
                                                size_t space) {
  hblock_ctx_t *block_ctx = reinterpret_cast<hblock_ctx_t *>(hblock_ctx_p);

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

  hblock_ctx_t *block_ctx = reinterpret_cast<hblock_ctx_t *>(hblock_ctx);
  std::unordered_map<std::string, std::string> &headers_map =
      *(block_ctx->decoded_headers_map);

  headers_map[headerKey] = headerValue;

  return 0;
}

void QpackCodec::Decode(
    void *context, std::vector<uint8_t> &encoded_headers,
    std::unordered_map<std::string, std::string> &decoded_headers_map) {
  HQUIC *stream = reinterpret_cast<HQUIC *>(context);

  std::vector<struct lsqpack_dec> dec(1);

  uint64_t stream_id{};
  auto len = static_cast<uint32_t>(sizeof(stream_id));
  if (QUIC_FAILED(ms_quic_->GetParam(*stream, QUIC_PARAM_STREAM_ID, &len,
                                     &stream_id))) {
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
  blockCtx.back().decoded_headers_map = &decoded_headers_map;

  const unsigned char *encoded_headersPtr = encoded_headers.data();
  size_t totalHeaderSize = encoded_headers.size();

  enum lsqpack_read_header_status readStatus;

  readStatus = lsqpack_dec_header_in(dec.data(), &blockCtx.back(), stream_id,
                                     totalHeaderSize, &encoded_headersPtr,
                                     totalHeaderSize, NULL, NULL);

  lsqpack_dec_cleanup(dec.data());
}
