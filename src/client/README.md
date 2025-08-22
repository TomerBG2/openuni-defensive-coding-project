# TCP Client Application

This project implements a simple TCP client using the Boost library with C++17. The client connects to a specified server, sends messages, and receives responses asynchronously.

## Project Structure

```
client
├── src
│   ├── main.cpp          # Entry point of the application
│   ├── tcp_client.cpp    # Implementation of the TCP client class
│   └── tcp_client.hpp    # Declaration of the TCP client class
├── CMakeLists.txt        # CMake configuration file
└── README.md             # Project documentation
```

## Requirements

- C++17
- Boost ASIO library

## Building the Project

1. Ensure you have CMake and Boost installed on your system.
2. Navigate to the project directory:

   ```bash
   cd /home/tomer/dev/uni_course/tmd/15/src/client
   ```

3. Create a build directory and navigate into it:

   ```bash
   mkdir build
   cd build
   ```

4. Run CMake to configure the project:

   ```bash
   cmake ..
   ```

5. Build the project:

   ```bash
   make
   ```

## Running the TCP Client

After building the project, you can run the TCP client executable. Make sure to specify the server address and port as needed.

```bash
./tcp_client <server_address> <port>
```

Replace `<server_address>` and `<port>` with the appropriate values for your server. 

## License

This project is licensed under the MIT License.