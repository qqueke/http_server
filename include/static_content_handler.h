// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file static_content_handler.h
 * @brief Defines the `StaticContentHandler` class for serving static content
 * over HTTP.
 *
 * This file contains the `StaticContentHandler` class that is responsible for
 * handling static content requests (such as HTML, CSS, JavaScript, images,
 * etc.), determining the appropriate content type for the file, and generating
 * the necessary headers for file transfers.
 */

#ifndef INCLUDE_STATIC_CONTENT_HANDLER_H_
#define INCLUDE_STATIC_CONTENT_HANDLER_H_

#include <array>
#include <cstdint>
#include <string>

#include "utils.h"

/**
 * @class StaticContentHandler
 * @brief Handles static content requests for file transfer and sets the
 * appropriate headers.
 *
 * The `StaticContentHandler` class is responsible for determining the content
 * type based on file extension, generating HTTP headers for file transfers, and
 * providing methods to serve static files over HTTP.
 */
class StaticContentHandler {
 public:
  /**
   * @brief Default constructor for the `StaticContentHandler` class.
   */
  StaticContentHandler() = default;

  /**
   * @brief Default destructor for the `StaticContentHandler` class.
   */
  ~StaticContentHandler() = default;

  /**
   * @brief Handles the file transfer for a given file path.
   *
   * This method reads the file at the given path and returns the file size. It
   * also sets the appropriate content type based on the file extension and
   * encoding type.
   *
   * @param file_path The path to the file to be transferred.
   * @param enc_types A string view representing any encoding types (e.g., gzip)
   * for the file.
   * @return The size of the file in bytes.
   */
  uint64_t HandleFile(std::string &file_path, const std::string_view enc_types);

  /**
   * @brief Builds the HTTP headers required for a file transfer.
   *
   * This method generates the appropriate headers for a file transfer,
   * including the content type and content length, based on the file path and
   * file size.
   *
   * @param file_path The path to the file to be transferred.
   * @param file_size The size of the file in bytes.
   * @return The generated HTTP headers as a string.
   */
  std::string BuildHeadersForFileTransfer(std::string &file_path,
                                          uint64_t file_size);

  static uint64_t CompressFileTmp(const std::string &in_file,
                                  const char *out_file, CompressionType type);

  static uint64_t TryCompressing(const std::string &file_path,
                                 std::string_view encoding,
                                 std::array<char, 128> &compressed_path);

 private:
  /**
   * @brief Retrieves the content type for a given file extension.
   *
   * This private helper function checks the file extension and returns the
   * corresponding content type. If the file extension is not recognized, it
   * returns an empty string.
   *
   * @param file_ext The file extension (e.g., ".html", ".jpg").
   * @return The content type for the given extension.
   */
  std::string_view GetContentType(const std::string &file_ext);

  /**
   * @brief Appends the content type header to the provided headers string.
   *
   * This private helper function appends the appropriate `Content-Type` header
   * to the headers string, based on the file extension.
   *
   * @param file_path The path to the file.
   * @param headers The headers string to which the content type will be
   * appended.
   */
  void AppendContentType(const std::string &file_path, std::string &headers);

  /**
   * @brief A static array of common content types indexed by file extension.
   *
   * This array maps common file extensions (e.g., ".html", ".css", ".jpg") to
   * their corresponding `Content-Type` headers. It is used to determine the
   * correct content type for a file based on its extension.
   */
  static constexpr std::array<std::pair<std::string_view, std::string_view>, 24>
      content_types_ = {{{".html", "Content-Type: text/html\r\n"},
                         {".css", "Content-Type: text/css\r\n"},
                         {".js", "Content-Type: text/javascript\r\n"},
                         {".json", "Content-Type: application/json\r\n"},
                         {".xml", "Content-Type: application/xml\r\n"},
                         {".txt", "Content-Type: text/plain\r\n"},
                         {".jpg", "Content-Type: image/jpeg\r\n"},
                         {".jpeg", "Content-Type: image/jpeg\r\n"},
                         {".png", "Content-Type: image/png\r\n"},
                         {".gif", "Content-Type: image/gif\r\n"},
                         {".svg", "Content-Type: text/svg\r\n"},
                         {".webp", "Content-Type: image/webp\r\n"},
                         {".mp3", "Content-Type: audio/mpeg\r\n"},
                         {".wav", "Content-Type: audio/wav\r\n"},
                         {".mp4", "Content-Type: video/mp4\r\n"},
                         {".webm", "Content-Type: video/webm\r\n"},
                         {".woff", "Content-Type: font/woff\r\n"},
                         {".woff2", "Content-Type: font/woff2\r\n"},
                         {".ttf", "Content-Type: font/ttf\r\n"},
                         {".otf", "Content-Type: font/otf\r\n"},
                         {".pdf", "Content-Type: application/pdf\r\n"},
                         {".zip", "Content-Type: application/zip\r\n"},
                         {".gz", "Content-Type: application/gzip\r\n"},
                         {".gzip", "Content-Type: application/gzip\r\n"}}};
};

#endif  // INCLUDE_STATIC_CONTENT_HANDLER_H_
