#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "../cryptopp_wrapper/AESWrapper.h"
#include "../cryptopp_wrapper/Base64Wrapper.h"
#include "../cryptopp_wrapper/RSAWrapper.h"
#include "../protocol_message.hpp"

struct ClientListEntry {
  std::array<u_int8_t, sizeof(ProtocolRequestHeader::client_id)> id;
  std::string name;  // 255 bytes, may contain nulls
  std::vector<uint8_t> public_key;
  std::string symmetric_key;
  bool has_valid_symmetric_key = false;
};

class ClientModel {
 public:
  static std::unique_ptr<ClientModel> create_from_file(
      const std::string& filename);

  ClientModel(const std::string& ip, const std::string& port);
  ~ClientModel();
  ClientModel(const ClientModel& other);
  ClientModel& operator=(const ClientModel& other);
  ClientModel(ClientModel&& other) noexcept;
  ClientModel& operator=(ClientModel&& other) noexcept;

  bool me_info_exists() const;
  void save_me_info(
      const std::string& username,
      const std::array<uint8_t, ProtocolMessage::CLIENT_ID_SIZE>& uuid,
      const std::string& private_key_base64);
  void load_my_info();

  const std::string& get_ip() const { return m_ip; }
  const std::string& get_port() const { return m_port; }

  const std::array<uint8_t, 16>& get_my_id() const { return m_my_id; }

  // Returns the stored private key
  std::string get_private_key() const;
  void set_client_list(const std::vector<ClientListEntry>& list);
  const std::vector<ClientListEntry>& get_client_list() const;
  void update_client_public_key(
      const std::array<u_int8_t, sizeof(ProtocolRequestHeader::client_id)>& id,
      const std::vector<uint8_t>& public_key);
  // Returns pointer to client entry by id, or nullptr if not found
  ClientListEntry* get_client_by_id(
      const std::array<u_int8_t, sizeof(ProtocolRequestHeader::client_id)>& id);
  const ClientListEntry* get_client_by_id(
      const std::array<u_int8_t, sizeof(ProtocolRequestHeader::client_id)>& id)
      const;

  // Returns pointer to client entry by name, or nullptr if not found
  ClientListEntry* get_client_by_name(const std::string& name);
  const ClientListEntry* get_client_by_name(const std::string& name) const;

  // Get a symmetric key for a specific client
  std::string get_symmetric_key_for_client(
      const std::array<uint8_t, sizeof(ProtocolRequestHeader::client_id)>&
          client_id) const {
    const ClientListEntry* client = get_client_by_id(client_id);
    if (client && client->has_valid_symmetric_key) {
      return client->symmetric_key;
    }
    // Return empty string if no key found
    return std::string();
  }

  // Set a symmetric key for a specific client
  void set_symmetric_key_for_client(
      const std::array<uint8_t, sizeof(ProtocolRequestHeader::client_id)>&
          client_id,
      const std::array<uint8_t, ProtocolMessage::SYM_KEY_SIZE>& key) {
    ClientListEntry* client = get_client_by_id(client_id);
    if (m_rsa_private_wrapper == nullptr) {
      throw std::runtime_error(
          "No RSA private wrapper available for decryption");
    }
    if (client) {
      std::string key_as_str = std::string(key.begin(), key.end());
      client->symmetric_key = m_rsa_private_wrapper->decrypt(key_as_str);
      client->has_valid_symmetric_key = true;
    }
  }

  // Check if we have a valid symmetric key for a client
  bool has_valid_symmetric_key_for_client(
      const std::array<uint8_t, sizeof(ProtocolRequestHeader::client_id)>&
          client_id) const {
    const ClientListEntry* client = get_client_by_id(client_id);
    return client && client->has_valid_symmetric_key;
  }

  // Legacy methods for backward compatibility
  std::array<uint8_t, ProtocolMessage::SYM_KEY_SIZE> get_symmetric_key() const {
    return m_symmetric_key;
  }

  void set_symmetric_key(
      const std::array<uint8_t, ProtocolMessage::SYM_KEY_SIZE>& key) {
    m_symmetric_key = key;
    m_has_valid_key = true;
  }

  bool has_valid_symmetric_key() const { return m_has_valid_key; }

  void generate_key_pair();

  std::string get_public_key() const { return m_public_key; }

  void set_my_uuid(std::array<uint8_t, ProtocolMessage::CLIENT_ID_SIZE> uuid) {
    m_my_id = uuid;
  }

 private:
  std::string m_ip;
  std::string m_port;
  std::vector<ClientListEntry> m_client_list;
  std::array<uint8_t, ProtocolMessage::SYM_KEY_SIZE> m_symmetric_key{};
  bool m_has_valid_key = false;
  std::string m_private_key;  // Stored in string format
  std::unique_ptr<RSAPrivateWrapper> m_rsa_private_wrapper;
  std::string m_public_key;
  std::array<uint8_t, 16> m_my_id{};
};