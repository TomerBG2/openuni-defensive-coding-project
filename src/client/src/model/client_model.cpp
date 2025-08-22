#include "client_model.hpp"
#include <algorithm>
#include <fstream>
#include <iomanip>
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
    : m_ip(ip), m_port(port) {}

ClientModel::~ClientModel() = default;

// Rule of 5
ClientModel::ClientModel(const ClientModel& other)
    : m_ip(other.m_ip), m_port(other.m_port) {}

ClientModel& ClientModel::operator=(const ClientModel& other) {
  if (this != &other) {
    m_ip = other.m_ip;
    m_port = other.m_port;
  }
  return *this;
}

ClientModel::ClientModel(ClientModel&& other) noexcept = default;
ClientModel& ClientModel::operator=(ClientModel&& other) noexcept = default;

bool ClientModel::me_info_exists() const {
  std::ifstream meFile("me.info");
  return meFile.good();
}

void ClientModel::save_me_info(const std::string& username,
                               const std::string& uuid) {
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
}

void ClientModel::set_client_list(const std::vector<ClientListEntry>& list) {
  m_client_list = list;
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

std::array<uint8_t, 16> ClientModel::load_my_id() const {
  std::ifstream meFile("me.info");
  if (!meFile)
    throw std::runtime_error("me.info not found");
  std::string username, uuid_hex;
  std::getline(meFile, username);
  std::getline(meFile, uuid_hex);
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
    return arr;
  } else {
    throw std::runtime_error("Invalid UUID format in me.info");
  }
}