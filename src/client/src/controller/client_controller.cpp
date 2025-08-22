#include "client_controller.hpp"
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include "../protocol_message.hpp"
#include "../protocol_server_response.hpp"
#include "../tcp_client.hpp"

ClientController::ClientController(std::unique_ptr<ClientModel> model,
                                   std::unique_ptr<ClientView> view)
    : m_model(std::move(model)), m_view(std::move(view)) {}

ClientController::~ClientController() = default;

void ClientController::run() {
  TcpClient client(m_model->get_ip(), m_model->get_port());
  client.connect();

  while (true) {
    try {
      ClientCommand cmd = m_view->prompt_command();
      switch (cmd) {
        case ClientCommand::Register: {
          if (m_model->me_info_exists()) {
            throw std::runtime_error(
                "me.info already exists. Registration aborted.");
          }
          std::string username = m_view->prompt_username();

          // TODO: Replace with real public key when available
          std::vector<uint8_t> public_key(ProtocolMessage::PUBLIC_KEY_SIZE,
                                          'a');

          ProtocolMessage msg =
              ProtocolMessage::create_register_request(username, public_key);
          auto bytes = msg.to_bytes();
          client.send(bytes);

          // Receive and parse reply using utility
          ProtocolServerResponse server_msg = recv_protocol_response(client);

          if (server_msg.code() != RESPONSE_CODES::REGISTER_REPLY ||
              server_msg.payload().size() != ProtocolMessage::CLIENT_ID_SIZE) {
            throw std::runtime_error(
                "Invalid register response from server. code: " +
                std::to_string(server_msg.code()) + " payload size: " +
                std::to_string(server_msg.payload().size()));
          }
          std::string uuid(server_msg.payload().begin(),
                           server_msg.payload().end());
          m_model->save_me_info(username, uuid);
          m_view->show_message(
              "Registration successful. UUID saved to me.info.");
          break;
        }
        case ClientCommand::ListClients: {
          // Build and send request using protocol API
          auto msg = ProtocolMessage::create_list_clients_request(
              m_model->load_my_id());
          client.send(msg.to_bytes());

          // Receive and parse response in one step
          ProtocolServerResponse server_msg = recv_protocol_response(client);
          if (server_msg.code() != RESPONSE_CODES::LIST_CLIENTS_REPLY) {
            throw std::runtime_error(
                "Invalid client list response from server.");
          }
          auto client_list = server_msg.parse_client_list();
          m_model->set_client_list(client_list);
          m_view->show_message("Client list received and saved.");
          m_view->show_all_clients(client_list);
          break;
        }
        case ClientCommand::PublicKey: {
          m_view->show_message("Enter client name: ");
          std::string target_name;
          std::getline(std::cin, target_name);
          const ClientListEntry* client_entry =
              m_model->get_client_by_name(target_name);
          if (!client_entry) {
            m_view->show_error(
                "Client name not found in client list. Please refresh the "
                "client list first.");
            break;
          }
          const auto& req_id = client_entry->id;
          ProtocolMessage msg = ProtocolMessage::create_public_key_request(
              m_model->load_my_id(), req_id);
          client.send(msg.to_bytes());
          ProtocolServerResponse server_msg = recv_protocol_response(client);

          std::vector<uint8_t> pubkey =
              server_msg.parse_public_key_reply(req_id);
          // Show client ID as hex
          m_view->show_message("Client ID:");
          m_view->show_hexify(req_id.data(), req_id.size());
          m_view->show_message("Public key (first 16 bytes): ");
          m_view->show_hexify(pubkey.data(), 16);
          m_model->update_client_public_key(req_id, pubkey);

          break;
        }
        case ClientCommand::Exit:
          return;
        case ClientCommand::Invalid:
          m_view->show_message("Invalid command");
          break;
        default:
          m_view->show_message("Command not implemented yet.");
          break;
      }
    } catch (const std::exception& e) {
      m_view->show_error(e.what());
    }
  }
}