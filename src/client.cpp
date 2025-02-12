#include "client.hpp"

#include <iostream>
#include <unordered_map>

#include "cCallbacks.hpp"
#include "utils.hpp"

extern std::unordered_map<HQUIC, std::unordered_map<std::string, std::string>>
    DecodedHeadersMap;

int dhiProcessHeader(void *hblock_ctx, struct lsxpack_header *xhdr) {
  // printf("dhi_process_header: xhdr=%lu\n", (size_t)xhdr);
  // printf("%.*s: %.*s\n", xhdr->name_len, (xhdr->buf + xhdr->name_offset),
  //        xhdr->val_len, (xhdr->buf + xhdr->val_offset));

  std::string headerKey(xhdr->buf + xhdr->name_offset, xhdr->name_len);
  std::string headerValue(xhdr->buf + xhdr->val_offset, xhdr->val_len);

  hblock_ctx_t *block_ctx = (hblock_ctx_t *)hblock_ctx;

  DecodedHeadersMap[block_ctx->stream][headerKey] = headerValue;

  return 0;
}

void UQPACKHeadersClient(HQUIC stream, std::vector<uint8_t> &encodedHeaders) {
  std::vector<struct lsqpack_dec> dec(1);

  struct lsqpack_dec_hset_if hset_if;
  hset_if.dhi_unblocked = dhiUnblocked;
  hset_if.dhi_prepare_decode = dhiPrepareDecode;
  hset_if.dhi_process_header = dhiProcessHeader;

  enum lsqpack_dec_opts dec_opts {};
  lsqpack_dec_init(dec.data(), NULL, 0x1000, 0, &hset_if, dec_opts);

  // hblock_ctx_t *blockCtx = (hblock_ctx_t *)malloc(sizeof(hblock_ctx_t));

  std::vector<hblock_ctx_t> blockCtx(1);

  memset(&blockCtx.back(), 0, sizeof(hblock_ctx_t));
  blockCtx.back().stream = stream;

  const unsigned char *encodedHeadersPtr = encodedHeaders.data();
  size_t totalHeaderSize = encodedHeaders.size();

  enum lsqpack_read_header_status readStatus;

  readStatus =
      lsqpack_dec_header_in(dec.data(), &blockCtx.back(), 100, totalHeaderSize,
                            &encodedHeadersPtr, totalHeaderSize, NULL, NULL);

  // printf("lsqpack_dec_header_in return = %d, const_end_header_buf = %lu, "
  //        "end_header_buf = %lu\n",
  //        read_status, (size_t)all_header_ptr, (size_t)all_header);

  // std::cout << "--------------------------------------------\n";
  // std::cout << "-----------Decoding finished ---------------\n";
  // std::cout << "--------------------------------------------\n";

  // std::cout << "Decoded headers:\n";
  // for (auto &[key, value] : DecodedHeadersMap[stream]) {
  //   std::cout << key << ": " << value << "\n";
  // }
}

// Parses stream buffer to retrieve headers payload and data payload
void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
                       std::string &data) {
  auto iter = streamBuffer.begin();

  while (iter < streamBuffer.end()) {
    // Ensure we have enough data for a frame (frameType + frameLength)
    if (std::distance(iter, streamBuffer.end()) < 3) {
      std::cout << "Error: Bad frame format (Not enough data)\n";
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
    case 0x01: // HEADERS frame
      std::cout << "[strm][" << Stream << "] Received HEADERS frame\n";

      {
        std::vector<uint8_t> encodedHeaders(iter, iter + frameLength);

        UQPACKHeadersClient(Stream, encodedHeaders);

        // headers = std::string(iter, iter + frameLength);
      }

      break;

    case 0x00: // DATA frame
      std::cout << "[strm][" << Stream << "] Received DATA frame\n";
      // Data might have been transmitted over multiple frames
      data += std::string(iter, iter + frameLength);
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

int QUIC_MAIN_EXPORT main(_In_ int argc,
                          _In_reads_(argc) _Null_terminated_ char *argv[]) {
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
    printf("MsQuicOpen2 failed, 0x%x!\n", Status);
    goto Error;
  }

  // Create a registration for the app's connections.
  if (QUIC_FAILED(Status =
                      MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
    printf("RegistrationOpen failed, 0x%x!\n", Status);
    goto Error;
  }

  if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
    PrintUsage();
  } else if (GetFlag(argc, argv, "client")) {
    RunClient(argc, argv);
  }
  // else if (GetFlag(argc, argv, "server")) {
  //    RunServer(argc, argv);
  // }
  else {
    PrintUsage();
  }

Error:

  if (MsQuic != NULL) {
    if (Configuration != NULL) {
      MsQuic->ConfigurationClose(Configuration);
    }
    if (Registration != NULL) {
      // This will block until all outstanding child objects have been
      // closed.
      MsQuic->RegistrationClose(Registration);
    }
    MsQuicClose(MsQuic);
  }

  return (int)Status;
}
