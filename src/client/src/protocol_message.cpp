#include "protocol_message.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

ProtocolMessage::ProtocolMessage(const ProtocolRequestHeader& header,
                                 const std::vector<uint8_t>& payload)
    : m_header(header), m_payload(payload) {}

std::vector<uint8_t> ProtocolMessage::to_bytes() const {
  ProtocolRequestHeader header_be = m_header;
  header_be.code = htons(header_be.code);
  header_be.payload_size = htonl(header_be.payload_size);

  std::vector<uint8_t> buf(sizeof(ProtocolRequestHeader));
  std::memcpy(buf.data(), &header_be, sizeof(ProtocolRequestHeader));
  buf.insert(buf.end(), m_payload.begin(), m_payload.end());
  return buf;
}

ProtocolMessage ProtocolMessage::from_bytes(const std::vector<uint8_t>& data) {
  if (data.size() < HEADER_SIZE)
    throw std::runtime_error("Message too short");
  ProtocolRequestHeader header;
  std::memcpy(&header, data.data(), HEADER_SIZE);
  header.code = ntohs(header.code);
  header.payload_size = ntohl(header.payload_size);
  if (data.size() < HEADER_SIZE + header.payload_size)
    throw std::runtime_error("Incomplete message");
  std::vector<uint8_t> payload(
      data.begin() + HEADER_SIZE,
      data.begin() + HEADER_SIZE + header.payload_size);
  return ProtocolMessage(header, payload);
}

// Helper for register request
ProtocolMessage ProtocolMessage::create_register_request(
    const std::string& username,
    const std::vector<uint8_t>& public_key) {
  ProtocolRequestHeader header{};
  header.client_id.fill(0);  // UUID_SIZE bytes of 0 for registration
  header.version = 1;
  header.code = REQUEST_CODES::REGISTER;

  std::vector<uint8_t> payload(
      ProtocolMessage::CLIENT_NAME_SIZE + ProtocolMessage::PUBLIC_KEY_SIZE, 0);
  std::memcpy(
      payload.data(), username.c_str(),
      std::min<size_t>(username.size(), ProtocolMessage::CLIENT_NAME_SIZE));
  if (public_key.size() >= ProtocolMessage::PUBLIC_KEY_SIZE) {
    std::memcpy(payload.data() + ProtocolMessage::CLIENT_NAME_SIZE,
                public_key.data(), ProtocolMessage::PUBLIC_KEY_SIZE);
  }
  // else leave as zeros

  header.payload_size = payload.size();

  return ProtocolMessage(header, payload);
}

ProtocolMessage ProtocolMessage::create_list_clients_request(
    const std::array<uint8_t, UUID_SIZE>& client_id) {
  ProtocolRequestHeader header{};
  header.client_id = client_id;
  header.version = 1;
  header.code = REQUEST_CODES::CLIENT_LIST;
  header.payload_size = 0;
  std::vector<uint8_t> payload;  // No payload
  return ProtocolMessage(header, payload);
}

ProtocolMessage ProtocolMessage::create_public_key_request(
    const std::array<uint8_t, UUID_SIZE>& my_id,
    const std::array<uint8_t, CLIENT_ID_SIZE>& target_id) {
  ProtocolRequestHeader header{};
  header.client_id = my_id;
  header.version = 1;
  header.code = REQUEST_CODES::PUBLIC_KEY_REQUEST;
  header.payload_size = CLIENT_ID_SIZE;
  std::vector<uint8_t> payload(target_id.begin(), target_id.end());
  return ProtocolMessage(header, payload);
}

ProtocolMessage ProtocolMessage::create_send_message_request(
    const std::array<uint8_t, UUID_SIZE>& my_id,
    const std::array<uint8_t, CLIENT_ID_SIZE>& dst_id,
    MessageType msg_type,
    const std::vector<uint8_t>& content) {
  ProtocolRequestHeader header{};
  header.client_id = my_id;
  header.version = 1;
  header.code = REQUEST_CODES::SEND_MESSAGE;

  std::vector<uint8_t> payload;
  // Append destination client ID
  payload.insert(payload.end(), dst_id.begin(), dst_id.end());
  // Append message type
  payload.push_back(static_cast<uint8_t>(msg_type));
  // Append content size (4 bytes, network order)
  uint32_t content_size = content.size();
  uint32_t content_size_n = htonl(content_size);
  uint8_t* size_ptr = reinterpret_cast<uint8_t*>(&content_size_n);
  payload.insert(payload.end(), size_ptr, size_ptr + 4);
  // Append content
  payload.insert(payload.end(), content.begin(), content.end());

  header.payload_size = payload.size();
  return ProtocolMessage(header, payload);
}

ProtocolMessage ProtocolMessage::create_symmetric_key_request(
    const std::array<uint8_t, UUID_SIZE>& my_id,
    const std::array<uint8_t, CLIENT_ID_SIZE>& dst_id) {
  ProtocolRequestHeader header{};
  header.client_id = my_id;
  header.version = 1;
  header.code = REQUEST_CODES::SEND_MESSAGE;

  std::vector<uint8_t> payload;
  // Append destination client ID
  payload.insert(payload.end(), dst_id.begin(), dst_id.end());
  // Append message type
  payload.push_back(static_cast<uint8_t>(MessageType::SYMMETRIC_KEY_REQUEST));
  // Append content size (4 bytes, network order) - zero
  uint32_t content_size_n = 0;
  uint8_t* size_ptr = reinterpret_cast<uint8_t*>(&content_size_n);
  payload.insert(payload.end(), size_ptr, size_ptr + 4);
  // No content

  header.payload_size = payload.size();
  return ProtocolMessage(header, payload);
}

ProtocolMessage ProtocolMessage::create_send_sym_key_message_request(
    const std::array<uint8_t, UUID_SIZE>& my_id,
    const std::array<uint8_t, CLIENT_ID_SIZE>& dst_id,
    const std::array<uint8_t, SYM_KEY_SIZE>& sym_key) {
  ProtocolRequestHeader header{};
  header.client_id = my_id;
  header.version = 1;
  header.code = REQUEST_CODES::SEND_MESSAGE;

  std::vector<uint8_t> payload;
  // Append destination client ID
  payload.insert(payload.end(), dst_id.begin(), dst_id.end());
  // Append message type
  payload.push_back(static_cast<uint8_t>(MessageType::SYMMETRIC_KEY_SEND));
  // Append content size (4 bytes, network order)
  uint32_t content_size = SYM_KEY_SIZE;
  uint32_t content_size_n = htonl(content_size);
  uint8_t* size_ptr = reinterpret_cast<uint8_t*>(&content_size_n);
  payload.insert(payload.end(), size_ptr, size_ptr + 4);
  // Append symmetric key content
  payload.insert(payload.end(), sym_key.begin(), sym_key.end());

  header.payload_size = payload.size();
  return ProtocolMessage(header, payload);
}

ProtocolMessage ProtocolMessage::create_pending_messages_request(
    const std::array<uint8_t, UUID_SIZE>& my_id) {
  ProtocolRequestHeader header{};
  header.client_id = my_id;
  header.version = 1;
  header.code = REQUEST_CODES::PENDING_MESSAGE_REQUEST;
  header.payload_size = 0;

  // No payload for pending messages request
  std::vector<uint8_t> payload;

  return ProtocolMessage(header, payload);
}