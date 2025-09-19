# Secure MessageU TCP Client Architecture

This client implements a secure messaging protocol for a university course, using C++17 and Boost.Asio. The design follows the Model-View-Controller (MVC) pattern and strictly encapsulates all protocol logic.

## Key Architecture

- **MVC Pattern:**  
  - **Controller:** Orchestrates user commands and delegates all protocol logic.  
    - `controller/client_controller.cpp`
  - **Model:** Stores client-side state (e.g., user info, session data).  
    - `model/`
  - **View:** Handles all user I/O (CLI, prompts, output).  
    - `view/`

- **Protocol Encapsulation:**  
  - **Request Creation:**  
    - All protocol requests are built using static methods in `protocol_message.hpp/cpp`.  
    - Controllers never construct protocol structs manually.
  - **Response Parsing:**  
    - All protocol responses are parsed and validated using methods in `protocol_server_response.hpp/cpp`.  
    - Controllers do not parse headers or payloads directly.

- **Networking:**  
  - Uses Boost.Asio for TCP communication, abstracted in `tcp_client.hpp/cpp`.

- **Binary Protocol:**  
  - All communication uses packed structs and binary data.  
  - Protocol sizes and codes are always derived from enums or `sizeof`, never hardcoded.
