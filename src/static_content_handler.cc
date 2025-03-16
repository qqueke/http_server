// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/static_content_handler.h"

#include <sys/stat.h>
#include <zlib.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "../include/log.h"
#include "../include/utils.h"

#define CHUNK_SIZE 16384
uint64_t StaticContentHandler::CompressFileTmp(const std::string &in_file,
                                               const char *out_file,
                                               CompressionType type) {
  std::ifstream in_file_stream(in_file, std::ios::binary);
  if (!in_file_stream) {
    LogError("Failed to open input file: " + in_file);
    return 0;
  }

  // Create output file
  std::ofstream out_file_stream(out_file, std::ios::binary | std::ios::out);
  out_file_stream.close();

  std::ofstream outFileStream(out_file, std::ios::binary);
  if (!outFileStream) {
    LogError("Failed to open output file: " + std::string(out_file));
    return 0;
  }

  // Will read file stream as chars until end of file ({}), to the vector
  std::vector<char> buffer(std::istreambuf_iterator<char>(in_file_stream), {});

  uLongf compressed_size = compressBound(buffer.size());
  std::vector<Bytef> compressed_data(compressed_size);

  z_stream z_stream = {};
  z_stream.next_in = reinterpret_cast<Bytef *>(buffer.data());
  z_stream.avail_in = buffer.size();
  z_stream.next_out = compressed_data.data();
  z_stream.avail_out = compressed_size;

  int window_bits = (type == GZIP) ? 15 + 16 : 15;

  if (deflateInit2(&z_stream, Z_BEST_COMPRESSION, Z_DEFLATED, window_bits, 8,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    LogError("Compression initialization failed\n");
    return 0;
  }
  std::vector<char> in_buffer(CHUNK_SIZE);
  std::vector<Bytef> out_buffer(CHUNK_SIZE);

  uint64_t total_compressed_size = 0;
  int err = 0;

  do {
    // Read a chunk of the file
    in_file_stream.read(in_buffer.data(), CHUNK_SIZE);
    std::streamsize bytes_read = in_file_stream.gcount();

    z_stream.next_in = reinterpret_cast<Bytef *>(in_buffer.data());
    z_stream.avail_in = static_cast<uInt>(bytes_read);

    // Compress until input is fully consumed
    do {
      z_stream.next_out = out_buffer.data();
      z_stream.avail_out = CHUNK_SIZE;

      err = deflate(&z_stream, in_file_stream.eof() ? Z_FINISH : Z_NO_FLUSH);

      if (err == Z_STREAM_ERROR) {
        LogError("Compression failed: stream error");
        deflateEnd(&z_stream);
        return 0;
      }

      size_t bytes_compressed = CHUNK_SIZE - z_stream.avail_out;
      outFileStream.write(reinterpret_cast<const char *>(out_buffer.data()),
                          bytes_compressed);
      total_compressed_size += bytes_compressed;
    } while (z_stream.avail_out == 0);
  } while (!in_file_stream.eof());

  deflateEnd(&z_stream);

  std::cout << ((type == GZIP) ? "Gzip" : "Deflate")
            << " compression successful: " << out_file << "\n";
  return total_compressed_size;
}
uint64_t StaticContentHandler::TryCompressing(
    const std::string &file_path, std::string_view encoding,
    std::array<char, 128> &compressed_path) {
  static constexpr std::array<std::pair<std::string, CompressionType>, 2>
      compression_types = {{{"gzip", GZIP}, {"deflate", DEFLATE}}};

  uint64_t file_size = 0;

  if (encoding == "*") {
    for (const auto &[compression_type_str, compression_type_enum] :
         compression_types) {
      if (std::snprintf(compressed_path.data(), compressed_path.size(),
                        "%s.%.*s", file_path.c_str(),
                        static_cast<int>(compression_type_str.size()),
                        compression_type_str.data()) < 0) {
        return 0;
      }

      file_size = CompressFileTmp(file_path, compressed_path.data(),
                                  compression_type_enum);

      if (file_size != 0) {
        return file_size;
      }
    }
  } else if (encoding == "gzip") {
    if (std::snprintf(compressed_path.data(), compressed_path.size(), "%s.%.*s",
                      file_path.c_str(), static_cast<int>(encoding.size()),
                      encoding.data()) < 0) {
      return 0;
    }

    file_size = CompressFileTmp(file_path, compressed_path.data(), GZIP);
  } else if (encoding == "deflate") {
    if (std::snprintf(compressed_path.data(), compressed_path.size(), "%s.%.*s",
                      file_path.c_str(), static_cast<int>(encoding.size()),
                      encoding.data()) < 0) {
      return 0;
    }

    file_size = CompressFileTmp(file_path, compressed_path.data(), DEFLATE);
  }

  return file_size;
}

uint64_t StaticContentHandler::FileHandler(std::string &file_path,
                                           const std::string_view enc_types) {
  uint64_t file_size = 0;

  file_path.insert(0, 1, '.');
  // The regular file might not exist but compressed verion might exist!
  // file_path = "./static/gdb.pdf";
  // No encoding accepted
  if (enc_types.empty()) {
    struct stat buf{};
    int error = stat(file_path.c_str(), &buf);

    // File exists
    if (error == 0) {
      file_size = buf.st_size;
    }

    return file_size;
  }

  std::array<char, 128> compressed_path{};
  size_t start = 0;
  size_t end = enc_types.find(',');

  while (end != std::string_view::npos) {
    // Extract encoding and remove any spaces
    std::string_view encoding = enc_types.substr(start, end - start);

    while (!encoding.empty() && encoding.front() == ' ') {
      encoding.remove_prefix(1);
    }
    while (!encoding.empty() && encoding.back() == ' ') {
      encoding.remove_suffix(1);
    }

    struct stat buf{};

    if (std::snprintf(compressed_path.data(), compressed_path.size(), "%s.%.*s",
                      file_path.c_str(), static_cast<int>(encoding.size()),
                      encoding.data()) < 0) {
      start = end + 1;
      end = enc_types.find(',', start);
      continue;
    }

    int error = stat(compressed_path.data(), &buf);

    // Compressed file already exists
    if (error == 0) {
      file_size = buf.st_size;
      file_path.append(".").append(encoding);
      return file_size;
    }

    file_size = TryCompressing(file_path, encoding, compressed_path);

    if (file_size != 0) {
      file_path.append(".").append(encoding);
      return file_size;
    }

    start = end + 1;
    end = enc_types.find(',', start);
  }

  // Process last encoding
  std::string_view encoding = enc_types.substr(start);

  if (!encoding.empty()) {
    struct stat buf{};
    // std::array<char, 128> compressed_path;

    if (std::snprintf(compressed_path.data(), compressed_path.size(), "%s.%.*s",
                      file_path.c_str(), static_cast<int>(encoding.size()),
                      encoding.data()) < 0) {
      return 0;
    }

    int error = stat(compressed_path.data(), &buf);

    // Compressed file already exists
    if (error == 0) {
      file_size = buf.st_size;
      file_path.append(".").append(encoding);
      return file_size;
    }

    file_size = TryCompressing(file_path, encoding, compressed_path);

    if (file_size != 0) {
      file_path.append(".").append(encoding);
      return file_size;
    }
  }
  // By here we could not compress the file nor find a compressed version
  struct stat buf{};
  int error = stat(file_path.c_str(), &buf);

  // File exists
  if (error == 0) {
    file_size = buf.st_size;
  }

  return file_size;
}

std::string StaticContentHandler::BuildHeadersForFileTransfer(
    std::string &file_path, uint64_t file_size) {
  std::string headers{};

  headers.append("HTTP/1.1 200 OK\r\nContent-Length: ")
      .append(std::to_string(file_size))
      .append("\r\n");

  headers.append("Content-Disposition: attachment; filename=\"")
      .append(file_path.substr(9))
      .append("\"\r\n");

  AppendContentType(file_path, headers);
  headers.append("\r\n");
  return headers;
}

std::string_view StaticContentHandler::GetContentType(
    const std::string &file_ext) {
  for (const auto &pair : content_types_) {
    if (file_ext == pair.first) {
      return pair.second;
    }
  }
  return "";
}

void StaticContentHandler::AppendContentType(const std::string &file_path,
                                             std::string &headers) {
  std::string file_ext{};
  for (int pos = static_cast<int>(file_path.size() - 1); pos >= 0; --pos) {
    if (file_path[pos] == '.') {
      file_ext = file_path.substr(pos, file_path.size() - pos);
      break;
    }
  }

  headers.append(std::string(GetContentType(file_ext))).append("\r\n");
}
