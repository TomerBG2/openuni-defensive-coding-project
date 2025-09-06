#include "client_model.hpp"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include "../protocol_message.hpp"

std::unique_ptr<ClientModel> ClientModel::create_from_file(
    const std::string& filename) {
  std::ifstream infoFile(filename);
  if (!infoFile) {
    throw std::runtime_error("server.info not found");
  }
  std::string line, ip, port;
  std::getline(infoFile, line);
  std::istringstream iss(line);
  std::getline(iss, ip, ':');
  std::getline(iss, port);
  return std::make_unique<ClientModel>(ip, port);
}

ClientModel::ClientModel(const std::string& ip, const std::string& port)
    : m_ip(ip), m_port(port), m_has_valid_key(false) {
  m_aes_wrapper = std::make_unique<AESWrapper>();
  m_private_key =
      std::string(reinterpret_cast<const char*>(m_aes_wrapper->getKey()),
                  AESWrapper::DEFAULT_KEYLENGTH);
}

ClientModel::~ClientModel() = default;

// // Rule of 5
// ClientModel::ClientModel(const ClientModel& other)
//     : m_ip(other.m_ip),
//       m_port(other.m_port),
//       m_symmetric_key(other.m_symmetric_key),
//       m_has_valid_key(other.m_has_valid_key) {}

// ClientModel& ClientModel::operator=(const ClientModel& other) {
//   if (this != &other) {
//     m_ip = other.m_ip;
//     m_port = other.m_port;
//     m_symmetric_key = other.m_symmetric_key;
//     m_has_valid_key = other.m_has_valid_key;
//   }
//   return *this;
// }

ClientModel::ClientModel(ClientModel&& other) noexcept = default;
ClientModel& ClientModel::operator=(ClientModel&& other) noexcept = default;

bool ClientModel::me_info_exists() const {
  std::ifstream meFile("me.info");
  return meFile.good();
}

void ClientModel::save_me_info(
    const std::string& username,
    const std::array<uint8_t, ProtocolMessage::CLIENT_ID_SIZE>& uuid,
    const std::string& private_key_base64) {
  std::ofstream out("me.info");
  if (!out) {
    throw std::runtime_error("Failed to write me.info.");
  }
  // Write username and UUID as hex string for human readability
  out << username << std::endl;
  for (unsigned char c : uuid) {
    out << std::hex << std::setw(2) << std::setfill('0')
        << (int)(unsigned char)c;
  }
  out << std::endl;

  // Write the private key in base64 format
  out << private_key_base64 << std::endl;
}

void ClientModel::set_client_list(const std::vector<ClientListEntry>& list) {
  // Preserve symmetric keys when updating the client list
  std::vector<ClientListEntry> updated_list = list;

  // Copy symmetric keys from old list to new list where client IDs match
  for (auto& new_entry : updated_list) {
    for (const auto& old_entry : m_client_list) {
      if (new_entry.id == old_entry.id) {
        new_entry.symmetric_key = old_entry.symmetric_key;
        new_entry.has_valid_symmetric_key = old_entry.has_valid_symmetric_key;
        new_entry.public_key = old_entry.public_key;
        new_entry.has_valid_public_key = old_entry.has_valid_public_key;
      }
    }
  }

  m_client_list = updated_list;
}

const std::vector<ClientListEntry>& ClientModel::get_client_list() const {
  return m_client_list;
}

void ClientModel::update_client_public_key(
    const std::array<u_int8_t, 16>& id,
    const std::vector<uint8_t>& public_key) {
  for (auto& entry : m_client_list) {
    if (entry.id == id) {
      entry.public_key = public_key;
      entry.has_valid_public_key = true;
      break;
    }
  }
}

ClientListEntry* ClientModel::get_client_by_id(
    const std::array<u_int8_t, 16>& id) {
  for (auto& entry : m_client_list) {
    if (entry.id == id)
      return &entry;
  }
  return nullptr;
}

const ClientListEntry* ClientModel::get_client_by_id(
    const std::array<u_int8_t, 16>& id) const {
  for (const auto& entry : m_client_list) {
    if (entry.id == id)
      return &entry;
  }
  return nullptr;
}

ClientListEntry* ClientModel::get_client_by_name(const std::string& name) {
  for (auto& entry : m_client_list) {
    if (entry.name == name)
      return &entry;
  }
  return nullptr;
}

const ClientListEntry* ClientModel::get_client_by_name(
    const std::string& name) const {
  for (const auto& entry : m_client_list) {
    if (entry.name == name)
      return &entry;
  }
  return nullptr;
}

void ClientModel::load_my_info() {
  std::ifstream meFile("me.info");
  if (!meFile) {
    std::cout << "me.info not found, proceeding without loading user info.\n";
    return;
  }
  std::string username, uuid_hex, private_key_base64;
  std::getline(meFile, username);
  std::getline(meFile, uuid_hex);

  std::getline(meFile, private_key_base64);

  // Remove whitespace
  uuid_hex.erase(std::remove_if(uuid_hex.begin(), uuid_hex.end(), ::isspace),
                 uuid_hex.end());
  if (uuid_hex.size() == ProtocolMessage::CLIENT_ID_SIZE * 2) {
    // Hex string
    std::array<uint8_t, ProtocolMessage::CLIENT_ID_SIZE> arr;
    for (size_t i = 0; i < ProtocolMessage::CLIENT_ID_SIZE; ++i) {
      std::string byte_str = uuid_hex.substr(i * 2, 2);
      arr[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    m_my_id = arr;

    // Store the private key in memory if it exists
    if (private_key_base64.empty()) {
      throw std::runtime_error("Invalid private key in me.info");
    }
    m_private_key = Base64Wrapper::decode(private_key_base64);
    m_rsa_private_wrapper = std::make_unique<RSAPrivateWrapper>(m_private_key);
    m_public_key = m_rsa_private_wrapper->getPublicKey();

  } else {
    throw std::runtime_error("Invalid UUID format in me.info");
  }
}

std::string ClientModel::get_private_key() const {
  // Return the stored private key
  return m_private_key;
}

void ClientModel::generate_key_pair() {
  m_rsa_private_wrapper = std::make_unique<RSAPrivateWrapper>();
  m_public_key = m_rsa_private_wrapper->getPublicKey();
  m_private_key = m_rsa_private_wrapper->getPrivateKey();
}
