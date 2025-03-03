#ifndef TRANSPORT_HPP
#define TRANSPORT_HPP

#include <cstdint>
#include <mutex>
#include <vector>

class ITransportManager {
public:
  virtual ~ITransportManager() = default;

  virtual int SendBatch(void *connection,
                        const std::vector<std::vector<uint8_t>> &bytes) = 0;

  virtual int Send(void *connection, const std::vector<uint8_t> &bytes) = 0;

  virtual int Read(void *connection, std::vector<uint8_t> &buffer,
                   uint32_t writeOffset) = 0;

  virtual int SendBatch_TS(void *connection,
                           const std::vector<std::vector<uint8_t>> &bytes,
                           std::mutex &mut) = 0;

  virtual int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
                      std::mutex &mut) = 0;

  virtual int Read_TS(void *connection, std::vector<uint8_t> &buffer,
                      uint32_t writeOffset, std::mutex &mut) = 0;
};

class TcpTransport : public ITransportManager {
private:
  uint32_t _retryCount;
  uint32_t _sendDelayMS;
  uint32_t _recvDelayMS;

public:
  TcpTransport();
  TcpTransport(uint32_t retryCount, uint32_t sendDelayMS, uint32_t recvDelayMS);

  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes) override;

  int Send(void *connection, const std::vector<uint8_t> &bytes) override;

  int Read(void *connection, std::vector<uint8_t> &buffer,
           uint32_t writeOffset) override;

  int SendBatch_TS(void *connection,
                   const std::vector<std::vector<uint8_t>> &bytes,
                   std::mutex &mut) override;

  int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
              std::mutex &mut) override;

  int Read_TS(void *connection, std::vector<uint8_t> &buffer,
              uint32_t writeOffset, std::mutex &mut) override;
};

class QuicTransport : public ITransportManager {
public:
  QuicTransport() = default;

  int SendBatch(void *connection,
                const std::vector<std::vector<uint8_t>> &bytes) override;

  int Send(void *connection, const std::vector<uint8_t> &bytes) override;

  int Read(void *connection, std::vector<uint8_t> &buffer,
           uint32_t writeOffset) override;

  int SendBatch_TS(void *connection,
                   const std::vector<std::vector<uint8_t>> &bytes,
                   std::mutex &mut) override;

  int Send_TS(void *connection, const std::vector<uint8_t> &bytes,
              std::mutex &mut) override;

  int Read_TS(void *connection, std::vector<uint8_t> &buffer,
              uint32_t writeOffset, std::mutex &mut) override;
};

#endif
