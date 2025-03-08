#ifndef TRANSPORT_HPP
#define TRANSPORT_HPP

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "msquic.h"

class ITransportManager {
public:
  virtual ~ITransportManager() = default;

  virtual int Send(void *connection, const std::vector<uint8_t> &bytes) = 0;

  virtual int SendBatch(void *connection,
                        const std::vector<std::vector<uint8_t>> &bytes) = 0;

  virtual int Read(void *connection, std::vector<uint8_t> &buffer,
                   uint32_t write_offset) = 0;

  virtual int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
                      std::mutex &mut) = 0;

  virtual int SendBatch_TS(void *connection,
                           const std::vector<std::vector<uint8_t>> &bytes,
                           std::mutex &mut) = 0;

  virtual int Read_TS(void *connection, std::vector<uint8_t> &buffer,
                      uint32_t write_offset, std::mutex &mut) = 0;
};

class TcpTransport : public ITransportManager {
public:
  TcpTransport();
  TcpTransport(uint32_t retry_count, uint32_t sendDelayMS,
               uint32_t recvDelayMS);

  int Send(void *connection, const std::vector<uint8_t> &bytes) override;

  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes) override;

  int SendFile(void *connection, int fd);

  int Read(void *connection, std::vector<uint8_t> &buffer,
           uint32_t write_offset) override;

  int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
              std::mutex &mut) override;

  int SendBatch_TS(void *connection,
                   const std::vector<std::vector<uint8_t>> &bytes,
                   std::mutex &mut) override;

  int Read_TS(void *connection, std::vector<uint8_t> &buffer,
              uint32_t write_offset, std::mutex &mut) override;

private:
  uint32_t _retry_count_;
  uint32_t _sendDelayMS_;
  uint32_t _recvDelayMS_;
};

class QuicTransport {
public:
  QuicTransport() = default;
  explicit QuicTransport(const QUIC_API_TABLE *ms_quic) : ms_quic_(ms_quic) {}

  int Send(void *connection, const std::vector<uint8_t> &bytes);

  int Send(void *connection, const std::vector<uint8_t> &bytes,
           enum QUIC_SEND_FLAGS flag);

  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes);

  int SendFile(void *connection, int fd);

  // int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
  //             std::mutex &mut);
  //
  // int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
  //             enum QUIC_SEND_FLAGS flag, std::mutex &mut);
  //
  // int SendBatch_TS(void *connection,
  //                  const std::vector<std::vector<uint8_t>> &bytes,
  //                  std::mutex &mut);

private:
  const QUIC_API_TABLE *ms_quic_;
};

#endif
