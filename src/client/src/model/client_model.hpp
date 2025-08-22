#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "../protocol_message.hpp"

struct ClientListEntry {
  std::array<u_int8_t, sizeof(ProtocolRequestHeader::client_id)> id;
  std::string name;  // 255 bytes, may contain nulls
  std::vector<uint8_t> public_key;
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
  void save_me_info(const std::string& username, const std::string& uuid);

  const std::string& get_ip() const { return m_ip; }
  const std::string& get_port() const { return m_port; }
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

  std::array<uint8_t, sizeof(ProtocolRequestHeader::client_id)> load_my_id()
      const;

 private:
  std::string m_ip;
  std::string m_port;
  std::vector<ClientListEntry> m_client_list;
};