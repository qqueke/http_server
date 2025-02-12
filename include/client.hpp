#ifndef CLIENT_HPP
#define CLIENT_HPP

#include "utils.hpp"

int dhiProcessHeader(void *hblock_ctx, struct lsxpack_header *xhdr);
void UQPACKHeadersClient(HQUIC stream, std::vector<uint8_t> &encodedHeaders);

void ParseStreamBuffer(HQUIC Stream, std::vector<uint8_t> &streamBuffer,
                       std::string &data);

void RunClient(_In_ int argc, _In_reads_(argc) _Null_terminated_ char *argv[]);

#endif
