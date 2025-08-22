#pragma once

#include <array>
#include <cstdint>
#include <vector>

static constexpr size_t UUID_SIZE = 16;

struct ProtocolRequestHeader {
  std::array<uint8_t, UUID_SIZE> client_id;
  uint8_t version;
  uint16_t code;
  uint32_t payload_size;
} __attribute__((packed));  // GCC/Clang: ensures no padding

class ProtocolMessage {
 public:
  static constexpr size_t CLIENT_ID_SIZE =
      sizeof(ProtocolRequestHeader::client_id);
  static constexpr size_t HEADER_SIZE = sizeof(ProtocolRequestHeader);
  static constexpr size_t CLIENT_NAME_SIZE = 255;
  static constexpr size_t PUBLIC_KEY_SIZE = 160;

  ProtocolMessage(const ProtocolRequestHeader& header,
                  const std::vector<uint8_t>& payload);

  std::vector<uint8_t> to_bytes() const;
  static ProtocolMessage from_bytes(const std::vector<uint8_t>& data);

  static ProtocolMessage create_register_request(
      const std::string& username,
      const std::vector<uint8_t>& public_key);
  static ProtocolMessage create_list_clients_request(
      const std::array<uint8_t, UUID_SIZE>& client_id);

  static ProtocolMessage create_public_key_request(
      const std::array<uint8_t, UUID_SIZE>& my_id,
      const std::array<uint8_t, CLIENT_ID_SIZE>& target_id);

  const ProtocolRequestHeader& header() const { return m_header; }
  const std::vector<uint8_t>& payload() const { return m_payload; }

 private:
  ProtocolRequestHeader m_header;
  std::vector<uint8_t> m_payload;
};

enum REQUEST_CODES {
  REGISTER = 600,
  CLIENT_LIST = 601,
  PUBLIC_KEY_REQUEST = 602
};