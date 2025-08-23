
#include "model/client_model.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include "protocol_server_response.hpp"

ProtocolServerResponse ProtocolServerResponse::from_bytes(
    const std::vector<uint8_t>& data) {
  if (data.size() < HEADER_SIZE)
    throw std::runtime_error("Response too short");
  ProtocolResponseHeader header;
  std::memcpy(&header, data.data(), HEADER_SIZE);
  header.code = ntohs(header.code);
  header.payload_size = ntohl(header.payload_size);
  if (data.size() < HEADER_SIZE + header.payload_size)
    throw std::runtime_error("Incomplete response");
  std::vector<uint8_t> payload(
      data.begin() + HEADER_SIZE,
      data.begin() + HEADER_SIZE + header.payload_size);
  return ProtocolServerResponse(header, payload);
}

std::vector<ClientListEntry> ProtocolServerResponse::parse_client_list() const {
  std::vector<ClientListEntry> client_list;
  size_t entry_size = sizeof(PackedClientListEntry);
  size_t count = m_payload.size() / entry_size;
  for (size_t i = 0; i < count; ++i) {
    const PackedClientListEntry* packed =
        reinterpret_cast<const PackedClientListEntry*>(m_payload.data() +
                                                       i * entry_size);
    ClientListEntry entry;
    for (size_t j = 0; j < UUID_SIZE; ++j)
      entry.id[j] = packed->id[j];
    std::string name_str(packed->name, ProtocolMessage::CLIENT_NAME_SIZE);
    size_t null_pos = name_str.find('\0');
    if (null_pos != std::string::npos)
      name_str.resize(null_pos);
    entry.name = name_str;
    client_list.push_back(entry);
  }
  return client_list;
}

std::vector<uint8_t> ProtocolServerResponse::parse_public_key_reply(
    const std::array<uint8_t, UUID_SIZE>& requested_id) const {
  if (code() != RESPONSE_CODES::PUBLIC_KEY_REPLY) {
    throw std::runtime_error("Invalid public key response from server.");
  }
  if (m_payload.size() !=
      ProtocolMessage::CLIENT_ID_SIZE + ProtocolMessage::PUBLIC_KEY_SIZE) {
    throw std::runtime_error("Invalid public key response payload size");
  }
  // Validate that the server id response is the same as the one we sent out
  if (!std::equal(requested_id.begin(), requested_id.end(),
                  m_payload.begin())) {
    throw std::runtime_error(
        "Server response client ID does not match requested client ID");
  }
  return std::vector<uint8_t>(
      m_payload.begin() + ProtocolMessage::CLIENT_ID_SIZE, m_payload.end());
}