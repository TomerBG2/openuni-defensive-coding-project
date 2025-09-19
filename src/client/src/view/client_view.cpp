#include "client_view.hpp"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

void ClientView::show_message(const std::string& msg) const {
  std::cout << msg << std::endl;
}

void ClientView::show_hexify(const unsigned char* buffer,
                             unsigned int length) const {
  std::ios::fmtflags f(std::cout.flags());
  std::cout << std::hex;
  for (size_t i = 0; i < length; i++)
    std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i])
              << (((i + 1) % 16 == 0) ? "\n" : " ");
  std::cout << std::endl;
  std::cout.flags(f);
}

void ClientView::show_error(const std::string& msg) const {
  std::cout << "Error: " << msg << std::endl;
}

std::string ClientView::prompt_username() const {
  std::cout << "Enter username: ";
  std::string username;
  std::getline(std::cin, username);
  return username;
}

ClientCommand ClientView::prompt_command() const {
  std::cout << "MessageU client at your service.\n\n"
               "110) Register\n"
               "120) Request for clients list\n"
               "130) Request for public key\n"
               "140) Request for waiting messages\n"
               "150) Send a text message\n"
               "151) Send a request for symmetric key\n"
               "152) Send your symmetric key\n"
               " 0) Exit client\n"
               "? ";
  std::string input;
  std::getline(std::cin, input);
  int code = -1;
  std::istringstream iss(input);
  iss >> code;
  if (iss.fail() || !iss.eof()) {
    std::cout << "input invalid " << input << std::endl;
    return ClientCommand::Invalid;
  }
  switch (code) {
    case 110:
      return ClientCommand::Register;
    case 120:
      return ClientCommand::ListClients;
    case 130:
      return ClientCommand::PublicKey;
    case 140:
      return ClientCommand::WaitingMessages;
    case 150:
      return ClientCommand::SendText;
    case 151:
      return ClientCommand::RequestSymKey;
    case 152:
      return ClientCommand::SendSymKey;
    case 0:
      return ClientCommand::Exit;
    default:
      std::cout << "input invalid 2 " << input << std::endl;

      return ClientCommand::Invalid;
  }
}

void ClientView::show_all_clients(
    const std::vector<ClientListEntry>& clients) const {
  std::cout << "Client List:" << std::endl;
  for (const auto& entry : clients) {
    std::cout << "ID: ";
    for (size_t i = 0; i < entry.id.size(); ++i) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << (int)entry.id[i];
    }
    std::cout << "  Name: " << entry.name << std::endl;
  }
  if (clients.empty()) {
    std::cout << "(No clients in list)" << std::endl;
  }
}

void ClientView::show_pending_message(const std::string& sender_name,
                                      uint8_t msg_type,
                                      const std::string& content) const {
  std::cout << "From: " << sender_name << std::endl;
  std::cout << "Content:" << std::endl;
  switch (static_cast<ProtocolMessage::MessageType>(msg_type)) {
    case ProtocolMessage::MessageType::SYMMETRIC_KEY_REQUEST:
      std::cout << "Request for symmetric key" << std::endl;
      break;
    case ProtocolMessage::MessageType::SYMMETRIC_KEY_SEND:
      std::cout << "Received symmetric key" << std::endl;
      break;
    case ProtocolMessage::MessageType::TEXT: {
      std::cout << content << std::endl;
      break;
    }
    default:
      std::cout << "Unknown message type" << std::endl;
      break;
  }
  std::cout << std::endl;
}