
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

  // first try to load existing user info
  m_model->load_my_info();

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
          m_model->generate_key_pair();
          // Get the private key for storage
          std::string private_key = m_model->get_private_key();
          std::string private_key_base64 = Base64Wrapper::encode(private_key);

          ProtocolMessage msg = ProtocolMessage::create_register_request(
              username, m_model->get_public_key());
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
          std::array<uint8_t, ProtocolMessage::CLIENT_ID_SIZE> uuid;
          std::copy(server_msg.payload().begin(), server_msg.payload().end(),
                    uuid.begin());
          m_model->set_my_uuid(uuid);

          m_model->save_me_info(username, uuid, private_key_base64);
          m_view->show_message(
              "Registration successful. UUID and private key saved to "
              "me.info.");
          break;
        }
        case ClientCommand::ListClients: {
          // Build and send request using protocol API
          m_view->show_message("sending get client with: ");
          m_view->show_hexify(m_model->get_my_id().data(),
                              m_model->get_my_id().size());
          auto msg = ProtocolMessage::create_list_clients_request(
              m_model->get_my_id());
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
              m_model->get_my_id(), req_id);
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

          // 1. Check if we have a symmetric key for this client
          if (!m_model->has_valid_symmetric_key_for_client(dst_id)) {
            throw std::runtime_error(
                "No valid symmetric key for this client. Please request a "
                "symmetric key first.");
            // 2. Get the symmetric key for this client
          }
          std::string sym_key = m_model->get_symmetric_key_for_client(dst_id);
          // 3. Create AES wrapper
          AESWrapper aes(
              reinterpret_cast<const unsigned char*>(sym_key.c_str()),
              sym_key.size());
          // 4. Encrypt the content
          std::string encrypted = aes.encrypt(
              reinterpret_cast<const char*>(content.data()), content.size());
          // 5. Update content with encrypted data
          content = std::vector<uint8_t>(encrypted.begin(), encrypted.end());

          // Build and send request using protocol API
          auto msg = ProtocolMessage::create_send_message_request(
              m_model->get_my_id(), dst_id, ProtocolMessage::MessageType::TEXT,
              content);
          client.send(msg.to_bytes());

          // Receive and validate the server response
          ProtocolServerResponse server_msg = recv_protocol_response(client);
          if (server_msg.code() != RESPONSE_CODES::SEND_MESSAGE_REPLY) {
            throw std::runtime_error(
                "Invalid server response after sending text message. Code: " +
                std::to_string(server_msg.code()));
          }

          m_view->show_message("Text message sent successfully.");
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
              m_model->get_my_id(), dst_id);
          client.send(msg.to_bytes());

          // Receive and validate the server response
          ProtocolServerResponse server_msg = recv_protocol_response(client);
          if (server_msg.code() != RESPONSE_CODES::SEND_MESSAGE_REPLY) {
            throw std::runtime_error(
                "Invalid server response after sending symmetric key "
                "request. "
                "Code: " +
                std::to_string(server_msg.code()));
          }

          m_view->show_message("Symmetric key request sent successfully.");
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
          if (!client_entry->has_valid_symmetric_key) {
            m_view->show_error(
                "No valid symmetric key for this client. Please request a "
                "symmetric key first.");
            break;
          }
          const auto& dst_id = client_entry->id;

          auto sym_key = m_model->get_symmetric_key();
          // TODO: encrypt the symmetric key with the recipient's public key
          // 1. Get recipient's public key
          const auto& recipient_public_key = client_entry->public_key;
          // 2. Create RSA wrapper with recipient's public key
          RSAPublicWrapper rsaPublic(std::string(recipient_public_key.begin(),
                                                 recipient_public_key.end()));
          // 3. Encrypt the symmetric key
          std::string encrypted_key = rsaPublic.encrypt(
              reinterpret_cast<const char*>(sym_key.data()), sym_key.size());

          // Build and send request using protocol API
          auto msg = ProtocolMessage::create_send_sym_key_message_request(
              m_model->get_my_id(), dst_id, sym_key);
          client.send(msg.to_bytes());

          // Receive and validate the server response
          ProtocolServerResponse server_msg = recv_protocol_response(client);
          if (server_msg.code() != RESPONSE_CODES::SEND_MESSAGE_REPLY) {
            throw std::runtime_error(
                "Invalid server response after sending symmetric key. "
                "Code: " +
                std::to_string(server_msg.code()));
          }

          m_view->show_message("Symmetric key sent successfully.");
          break;
        }

        case ClientCommand::WaitingMessages: {
          // Send pending message request using protocol API
          auto msg = ProtocolMessage::create_pending_messages_request(
              m_model->get_my_id());
          client.send(msg.to_bytes());
          ProtocolServerResponse server_msg = recv_protocol_response(client);

          // Verify correct response code
          if (server_msg.code() != RESPONSE_CODES::PENDING_MESSAGES_REPLY) {
            throw std::runtime_error(
                "Invalid pending messages response from server. Code: " +
                std::to_string(server_msg.code()));
          }

          // Parse all messages from payload
          const auto& payload = server_msg.payload();
          size_t offset = 0;
          // Each message has:
          // [CLIENT_ID][MSG_ID][MSG_TYPE][MSG_SIZE][CONTENT]
          const size_t MSG_ID_SIZE = 4;    // uint32_t
          const size_t MSG_TYPE_SIZE = 1;  // uint8_t
          const size_t MSG_SIZE_SIZE = 4;  // uint32_t
          const size_t MSG_HEADER_SIZE = ProtocolMessage::CLIENT_ID_SIZE +
                                         MSG_ID_SIZE + MSG_TYPE_SIZE +
                                         MSG_SIZE_SIZE;

          // Log total payload size for debugging
          m_view->show_message(
              "Received payload of " + std::to_string(payload.size()) +
              " bytes with " +
              std::to_string(payload.size() / MSG_HEADER_SIZE) +
              " potential messages");

          while (offset + MSG_HEADER_SIZE <= payload.size()) {
            // Log current offset for debugging
            m_view->show_message("Processing message at offset " +
                                 std::to_string(offset));

            // Parse header
            std::array<uint8_t, ProtocolMessage::CLIENT_ID_SIZE> from_id;
            std::memcpy(from_id.data(), payload.data() + offset,
                        ProtocolMessage::CLIENT_ID_SIZE);
            offset += ProtocolMessage::CLIENT_ID_SIZE;

            uint32_t msg_id = ntohl(
                *reinterpret_cast<const uint32_t*>(payload.data() + offset));
            offset += MSG_ID_SIZE;

            uint8_t msg_type = payload[offset++];  // Already only 1 byte
            m_view->show_message("Message type: " + std::to_string(msg_type));

            // Validate message type before proceeding
            if (msg_type < 1 || msg_type > 3) {
              m_view->show_error("Invalid message type: " +
                                 std::to_string(msg_type));
              break;  // Skip invalid message
            }

            // Make sure we have enough bytes for the size field
            if (offset + MSG_SIZE_SIZE > payload.size()) {
              m_view->show_error("Incomplete message header at offset " +
                                 std::to_string(offset));
              break;
            }

            // Safely extract message size
            uint32_t msg_size = 0;
            std::memcpy(&msg_size, payload.data() + offset, MSG_SIZE_SIZE);
            msg_size = ntohl(msg_size);
            offset += MSG_SIZE_SIZE;

            m_view->show_message(
                "Message size: " + std::to_string(msg_size) +
                " bytes (offset: " + std::to_string(offset) +
                ", payload size: " + std::to_string(payload.size()) + ")");

            // Validate message size
            if (offset + msg_size > payload.size()) {
              m_view->show_error("Message content exceeds payload bounds");
              break;
            }

            // Extract message content
            std::vector<uint8_t> content;
            try {
              if (msg_size > 0) {
                content.assign(payload.begin() + offset,
                               payload.begin() + offset + msg_size);
              }
              offset += msg_size;
            } catch (const std::exception& e) {
              m_view->show_error("Error extracting message content: " +
                                 std::string(e.what()));
              break;
            }

            // Find sender name
            const ClientListEntry* sender = m_model->get_client_by_id(from_id);
            if (!sender) {
              m_view->show_error(
                  "Sender ID not found in client list. Cannot display "
                  "message.");
              continue;  // Skip messages from unknown senders
            }
            std::string sender_name = sender ? sender->name : "<unknown>";
            m_view->show_message("Sender: " + sender_name);

            // // Check if we have a valid key for this client's messages
            // bool has_key = false;
            // // For TEXT messages, we need the symmetric key
            // if (msg_type ==
            //     static_cast<uint8_t>(ProtocolMessage::MessageType::TEXT)) {
            //   // Use the model to check if we have a valid symmetric key
            //   has_key = m_model->has_valid_symmetric_key_for_client(from_id);
            //   m_view->show_message("Text message, has key: " +
            //                        std::string(has_key ? "yes" : "no"));
            // } else {
            //   // For other message types, public key is sufficient
            //   has_key = !sender->public_key.empty();
            // }

            // Handle message based on type
            if (msg_type ==
                static_cast<uint8_t>(
                    ProtocolMessage::MessageType::SYMMETRIC_KEY_SEND)) {
              // Ensure we have valid content data
              if (content.size() >= ProtocolMessage::SYM_KEY_SIZE) {
                try {
                  // Safely convert vector<uint8_t> to array<uint8_t, SYM_KEY_SIZE>
                  std::array<uint8_t, ProtocolMessage::SYM_KEY_SIZE> sym_key = {};
                  // Only copy the exact amount needed
                  std::copy_n(content.begin(), 
                             std::min(content.size(), (size_t)ProtocolMessage::SYM_KEY_SIZE),
                             sym_key.begin());

                  // Store the symmetric key for this specific client
                  m_model->set_and_decrypt_symmetric_key_for_client(from_id,
                                                                    sym_key);

                  // Update has_key status based on the model's per-client
                  // status
                  // has_key =
                  //     m_model->has_valid_symmetric_key_for_client(from_id);
                } catch (const std::exception& e) {
                  m_view->show_error("Error processing symmetric key: " +
                                     std::string(e.what()));
                  break;
                }
              }
            }

            // Nothing to do here but display
            if (msg_type ==
                static_cast<uint8_t>(
                    ProtocolMessage::MessageType::SYMMETRIC_KEY_REQUEST)) {
            }

            // Display message using view helper
            if (sender) {
              // For TEXT messages, ensure content is not empty and decrypt if
              // needed
              if (msg_type ==
                  static_cast<uint8_t>(ProtocolMessage::MessageType::TEXT)) {
                if (content.empty()) {
                  m_view->show_error(
                      "Received TEXT message with empty content. Skipping "
                      "display.");
                } else {
                  std::string sym_key =
                      m_model->get_symmetric_key_for_client(from_id);
                  // Decrypt content
                  AESWrapper aes(
                      reinterpret_cast<const unsigned char*>(sym_key.c_str()),
                      sym_key.size());
                  std::string decrypted =
                      aes.decrypt(reinterpret_cast<const char*>(content.data()),
                                  content.size());
                  m_view->show_pending_message(sender_name, msg_type,
                                               decrypted);
                }

              } else {
                // For non-text messages, display as is
                std::string empty;
                m_view->show_pending_message(sender_name, msg_type, empty);
              }
            } else {
              m_view->show_error(
                  "Message from unknown sender - cannot display");
            }
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
