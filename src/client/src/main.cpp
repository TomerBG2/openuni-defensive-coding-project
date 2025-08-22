#include <iostream>
#include <memory>
#include "model/client_model.hpp"
#include "view/client_view.hpp"
#include "controller/client_controller.hpp"

int main() {
    try {
        auto model = ClientModel::create_from_file("server.info");
        auto view = std::make_unique<ClientView>();
        ClientController controller(std::move(model), std::move(view));
        controller.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}