#pragma once
#include <arpa/inet.h>
#include <cstdint>
#include <vector>
#include "tcp_client.hpp"

struct PackedClientListEntry {
  uint8_t id[ProtocolMessage::CLIENT_ID_SIZE];
  char name[ProtocolMessage::CLIENT_NAME_SIZE];
} __attribute__((packed));

struct ProtocolResponseHeader {
  uint8_t version;
  uint16_t code;
  uint32_t payload_size;
} __attribute__((packed));

class ProtocolServerResponse {
 public:
  static constexpr size_t HEADER_SIZE = sizeof(ProtocolResponseHeader);

  ProtocolServerResponse(const ProtocolResponseHeader& header,
                         const std::vector<uint8_t>& payload)
      : m_header(header), m_payload(payload) {}

  static ProtocolServerResponse from_bytes(const std::vector<uint8_t>& data);

  const ProtocolResponseHeader& header() const { return m_header; }
  const std::vector<uint8_t>& payload() const { return m_payload; }

  const uint16_t code() const { return m_header.code; }

  std::vector<ClientListEntry> parse_client_list() const;

  // Parse and validate public key reply. Throws on error. Returns the public
  // key vector.
  std::vector<uint8_t> parse_public_key_reply(
      const std::array<uint8_t, UUID_SIZE>& requested_id) const;

 private:
  ProtocolResponseHeader m_header;
  std::vector<uint8_t> m_payload;
};

enum RESPONSE_CODES {
  REGISTER_REPLY = 2100,
  LIST_CLIENTS_REPLY = 2101,
  PUBLIC_KEY_REPLY = 2102
};

// Utility: receive and parse a ProtocolServerResponse from a TcpClient
inline ProtocolServerResponse recv_protocol_response(TcpClient& client) {
  auto resp_header_bytes =
      client.receive_n_bytes(ProtocolServerResponse::HEADER_SIZE);
  ProtocolResponseHeader resp_header;
  std::memcpy(&resp_header, resp_header_bytes.data(),
              ProtocolServerResponse::HEADER_SIZE);
  resp_header.code = ntohs(resp_header.code);
  resp_header.payload_size = ntohl(resp_header.payload_size);
  auto payload_bytes = client.receive_n_bytes(resp_header.payload_size);
  return ProtocolServerResponse(resp_header, payload_bytes);
}