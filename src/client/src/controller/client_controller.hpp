#pragma once
#include <memory>
#include "../model/client_model.hpp"
#include "../view/client_view.hpp"

class ClientController {
 public:
  ClientController(std::unique_ptr<ClientModel> model,
                   std::unique_ptr<ClientView> view);
  ~ClientController();
  ClientController(const ClientController& other) = delete;
  ClientController& operator=(const ClientController& other) = delete;
  ClientController(ClientController&& other) noexcept = default;
  ClientController& operator=(ClientController&& other) noexcept = default;

  void run();

 private:
  std::unique_ptr<ClientModel> m_model;
  std::unique_ptr<ClientView> m_view;
};