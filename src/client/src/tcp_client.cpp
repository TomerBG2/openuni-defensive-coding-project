#include "tcp_client.hpp"
#include <boost/asio/connect.hpp>
#include <iostream>

TcpClient::TcpClient(const std::string& ip, const std::string& port)
    : m_ip(ip),
      m_port(port),
      m_ioContext(std::make_unique<boost::asio::io_context>()),
      m_socket(std::make_unique<boost::asio::ip::tcp::socket>(*m_ioContext)),
      m_connected(false) {}

TcpClient::~TcpClient() {
  if (m_socket && m_socket->is_open()) {
    boost::system::error_code ec;
    m_socket->close(ec);
  }
}

TcpClient::TcpClient(const TcpClient& other)
    : m_ip(other.m_ip),
      m_port(other.m_port),
      m_ioContext(std::make_unique<boost::asio::io_context>()),
      m_socket(std::make_unique<boost::asio::ip::tcp::socket>(*m_ioContext)),
      m_connected(other.m_connected) {}

TcpClient& TcpClient::operator=(const TcpClient& other) {
  if (this != &other) {
    m_ip = other.m_ip;
    m_port = other.m_port;
    m_ioContext = std::make_unique<boost::asio::io_context>();
    m_socket = std::make_unique<boost::asio::ip::tcp::socket>(*m_ioContext);
    m_connected = other.m_connected;
  }
  return *this;
}

TcpClient::TcpClient(TcpClient&& other) noexcept
    : m_ip(std::move(other.m_ip)),
      m_port(std::move(other.m_port)),
      m_ioContext(std::move(other.m_ioContext)),
      m_socket(std::move(other.m_socket)),
      m_connected(other.m_connected) {
  other.m_connected = false;
}

TcpClient& TcpClient::operator=(TcpClient&& other) noexcept {
  if (this != &other) {
    m_ip = std::move(other.m_ip);
    m_port = std::move(other.m_port);
    m_ioContext = std::move(other.m_ioContext);
    m_socket = std::move(other.m_socket);
    m_connected = other.m_connected;
    other.m_connected = false;
  }
  return *this;
}

void TcpClient::connect() {
  boost::asio::ip::tcp::resolver resolver(*m_ioContext);
  auto endpoints = resolver.resolve(m_ip, m_port);
  boost::asio::connect(*m_socket, endpoints);
  m_connected = true;
}

void TcpClient::send(const std::vector<uint8_t>& data) {
  if (!m_connected)
    throw std::runtime_error("Not connected");
  boost::asio::write(*m_socket, boost::asio::buffer(data.data(), data.size()));
}

std::vector<uint8_t> TcpClient::receive_n_bytes(size_t n) {
  if (!m_connected)
    throw std::runtime_error("Not connected");
  std::vector<uint8_t> buf(n);
  size_t received = 0;
  while (received < n) {
    size_t n_read = m_socket->read_some(
        boost::asio::buffer(buf.data() + received, n - received));
    if (n_read == 0)
      throw std::runtime_error("Connection closed by server");
    received += n_read;
  }
  return buf;
}