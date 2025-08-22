#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <string>

class TcpClient {
 public:
  TcpClient(const std::string& ip, const std::string& port);
  ~TcpClient();
  TcpClient(const TcpClient& other);
  TcpClient& operator=(const TcpClient& other);
  TcpClient(TcpClient&& other) noexcept;
  TcpClient& operator=(TcpClient&& other) noexcept;

  void connect();
  void send(const std::vector<uint8_t>& data);
  std::vector<uint8_t> receive_n_bytes(size_t n);

 private:
  std::string m_ip;
  std::string m_port;
  std::unique_ptr<boost::asio::io_context> m_ioContext;
  std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;
  bool m_connected;
};