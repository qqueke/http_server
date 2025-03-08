#ifndef STATIC_CONTENT_HANDLER_HPP
#define STATIC_CONTENT_HANDLER_HPP

#include <array>
#include <cstdint>
#include <string>
class StaticContentHandler {
public:
  StaticContentHandler();
  ~StaticContentHandler();

  uint64_t FileHandler(std::string &file_path,
                       const std::string_view enc_types);

  std::string BuildHeadersForFileTransfer(std::string &file_path,
                                          uint64_t file_size);

private:
  std::string_view GetContentType(const std::string &file_ext);

  void AppendContentType(const std::string &file_path, std::string &headers);
  // O(n) but I think we can do better
  static constexpr std::array<std::pair<std::string_view, std::string_view>, 23>
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
                         {".gz", "Content-Type: application/gzip\r\n"}}};
};

#endif
