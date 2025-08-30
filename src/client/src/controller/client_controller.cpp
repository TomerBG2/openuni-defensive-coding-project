
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
        case ClientCommand::SendText: {
          // Prompt for recipient username
          m_view->show_message("Enter recipient client name: ");
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
          const auto& dst_id = client_entry->id;
          // Prompt for message content
          m_view->show_message("Enter message text: ");
          std::string message_text;
          std::getline(std::cin, message_text);
          std::vector<uint8_t> content(message_text.begin(),
                                       message_text.end());
          // Build and send request using protocol API
          auto msg = ProtocolMessage::create_send_message_request(
              m_model->load_my_id(), dst_id, ProtocolMessage::MessageType::TEXT,
              content);
          client.send(msg.to_bytes());
          m_view->show_message("Text message sent.");
          break;
        }

        case ClientCommand::RequestSymKey: {
          // Prompt for recipient username
          m_view->show_message("Enter recipient client name: ");
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
          const auto& dst_id = client_entry->id;
          // Build and send request using protocol API (no content)
          auto msg = ProtocolMessage::create_symmetric_key_request(
              m_model->load_my_id(), dst_id);
          client.send(msg.to_bytes());
          m_view->show_message("Symmetric key request sent.");
          break;
        }

        case ClientCommand::SendSymKey: {
          // Prompt for recipient username
          m_view->show_message("Enter recipient client name: ");
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
          const auto& dst_id = client_entry->id;
          // Get symmetric key from model
          auto sym_key = m_model->get_symmetric_key();
          // Build and send request using protocol API
          auto msg = ProtocolMessage::create_send_sym_key_message_request(
              m_model->load_my_id(), dst_id, sym_key);
          client.send(msg.to_bytes());
          m_view->show_message("Symmetric key sent.");
          break;
        }

        case ClientCommand::WaitingMessages: {
          // Send pending message request using protocol API
          auto msg = ProtocolMessage::create_pending_messages_request(
              m_model->load_my_id());
          client.send(msg.to_bytes());
          ProtocolServerResponse server_msg = recv_protocol_response(client);

          // Parse all messages from payload
          const auto& payload = server_msg.payload();
          size_t offset = 0;
          // Each message has: [CLIENT_ID][MSG_ID][MSG_TYPE][MSG_SIZE][CONTENT]
          const size_t MSG_ID_SIZE = 4;    // uint32_t
          const size_t MSG_TYPE_SIZE = 1;  // uint8_t
          const size_t MSG_SIZE_SIZE = 4;  // uint32_t
          const size_t MSG_HEADER_SIZE = ProtocolMessage::CLIENT_ID_SIZE +
                                         MSG_ID_SIZE + MSG_TYPE_SIZE +
                                         MSG_SIZE_SIZE;

          while (offset + MSG_HEADER_SIZE <= payload.size()) {
            // Parse header
            std::array<uint8_t, ProtocolMessage::CLIENT_ID_SIZE> from_id;
            std::memcpy(from_id.data(), payload.data() + offset,
                        ProtocolMessage::CLIENT_ID_SIZE);
            offset += ProtocolMessage::CLIENT_ID_SIZE;

            uint32_t msg_id = ntohl(
                *reinterpret_cast<const uint32_t*>(payload.data() + offset));
            offset += MSG_ID_SIZE;

            uint8_t msg_type = payload[offset++];  // Already only 1 byte

            uint32_t msg_size = ntohl(
                *reinterpret_cast<const uint32_t*>(payload.data() + offset));
            offset += MSG_SIZE_SIZE;

            // Validate message size
            if (offset + msg_size > payload.size())
              break;

            // Extract message content
            std::vector<uint8_t> content(payload.begin() + offset,
                                         payload.begin() + offset + msg_size);
            offset += msg_size;

            // Find sender name
            const ClientListEntry* sender = m_model->get_client_by_id(from_id);
            std::string sender_name = sender ? sender->name : "<unknown>";
            bool has_key = sender && !sender->public_key.empty();

            // Handle message based on type
            if (msg_type ==
                static_cast<uint8_t>(
                    ProtocolMessage::MessageType::SYMMETRIC_KEY_SEND)) {
              if (content.size() == ProtocolMessage::SYM_KEY_SIZE) {
                m_model->update_client_public_key(
                    from_id, content);  // reuse as key storage
              }
            }

            // Display message using view helper
            m_view->show_pending_message(sender_name, msg_type, content,
                                         has_key);
          }
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