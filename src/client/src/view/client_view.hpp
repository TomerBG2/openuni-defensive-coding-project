#pragma once
#include <string>
#include <vector>
#include "../model/client_model.hpp"

enum class ClientCommand {
  Register = 110,
  ListClients = 120,
  PublicKey = 130,
  WaitingMessages = 140,
  SendText = 150,
  RequestSymKey = 151,
  SendSymKey = 152,
  Exit = 0,
  Invalid
};

class ClientView {
 public:
  void show_message(const std::string& msg) const;
  void show_hexify(const unsigned char* buffer, unsigned int length) const;
  void show_error(const std::string& msg) const;
  std::string prompt_username() const;
  ClientCommand prompt_command() const;

  // Print all clients' IDs and names
  void show_all_clients(const std::vector<ClientListEntry>& clients) const;
};