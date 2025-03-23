# HTTP Server

This is a simple HTTP server implementation with SSL/TLS support using OpenSSL, `ls-qpack`, and `msquic`. It includes both server and client functionalities.

![Alt Text](https://raw.githubusercontent.com/qqueke/http_server/refs/heads/gRpc/images/Server%20architecture.svg)

## Requirements

- **Linux** (other OS may work, but this has been tested on Linux)
- **OpenSSL** (for SSL/TLS support)
- **CMake** (for building the project)
- **Make** (to build the project)
- **Git** (to clone the repository)

## Dependencies

Before you begin, make sure you have the following dependencies installed:

### Required Tools

- **OpenSSL**: For SSL/TLS support.

  - **Linux**:
    - Ubuntu/Debian: `sudo apt-get install openssl libssl-dev`
    - RHEL 8: `sudo dnf install openssl-devel`
  - **macOS**: `brew install openssl`

- **CMake**: For building external libraries.

  - **Linux**:
    - Ubuntu/Debian: `sudo apt-get install cmake`
    - RHEL 8: Download the x86_64 Linux installation script from [cmake.org](https://cmake.org/download/) and run:
      ```bash
      sudo sh cmake.sh --prefix=/usr/local/ --exclude-subdir
      ```
  - **macOS**: `brew install cmake`

- **Make**: For building the project.

  - **Linux**: `sudo apt-get install make`
  - **macOS**: `brew install make`

- **Git**: To clone the repository.

  - **Linux**: `sudo apt-get install git`
  - **macOS**: `brew install git`

- **LTTng**: To build msquic lib (Linux Only).

  ```bash
  # Add the PPA repository for stable LTTng version
  sudo apt-add-repository ppa:lttng/stable-2.13

  # Update package lists
  sudo apt-get update

  # Install required packages
  sudo apt-get install build-essential liblttng-ust-dev lttng-tools
  ```

### Additional Dependencies for RHEL 8

On RHEL 8, you will need to install the following additional dependencies:

```bash
sudo dnf install libatomic
```

This project depends on three external libraries (submodules):

- **ls-qpack** (a library for HTTP/3 compression)
- **ls-hpack** (a library for HTTP/2 compression)
- **msquic** (Microsoft's QUIC implementation)

Lastly grpc and protobuf are required to be installed and you might have to change the CMakeLists.txt prefix path with your grpc and protobuf directories.

## Build

### 1. Clone the repository with submodules

To clone the repository along with its submodules, use the following command:

```bash
git clone --recurse-submodules https://github.com/qqueke/http_server.git
cd http_server
```

If you forgot to clone with `recurse--submodules` option, you can initialize and update the submodules by running:

```bash
git submodule update --init --recursive
```

### 2. Build the dependencies

Create build directory, navigate into it.

```bash
mkdir -p build && cd build/
```

Build the project with:

```bash
cmake ..
make
```

### 3. Generate SSL Certificates

You need to generate SSL certificates for the server. Use OpenSSL to generate the certificate and private key:

```bash
mkdir -p certificates

# Generate the private key
openssl genpkey -algorithm RSA -out certificates/server.key -aes256

# Generate the self-signed certificate
openssl req -new -x509 -key certificates/server.key -out certificates/server.crt -days 365
```

**Note**: If you don't want to use a passphrase for the private key, you can remove it with:

```bash
openssl rsa -in certificates/server.key -out certificates/server.key
```

### 4. Running the Server

```bash
./server -server -cert_file:certificates/server.crt -key_file:certificates/server.key
```

### 5. Running the Client

To run the client, you need to specify the server's IP address and port, and indicate that the connection is unencrypted (unless you're using SSL):

```bash
./client -client -target:<ipAddr>:<port> -unsecure
```

You can also specify a file containing multiple HTTP requests to be sent by the client. Use the --requests argument to specify the path to the requests file:

```bash
./client -client -target:<ipAddr>:<port> -unsecure --requests:requests.txt
```

Where `requests.txt` is a file formatted as follows:

```text
GET /hello HTTP/1.1
Host: qqueke
User-Agent: custom-client/1.0
Accept: */*


GET /goodbye HTTP/1.1
Host: qqueke
User-Agent: custom-client/1.0
Accept: */*

Body: Goodbye, World!
```

## Arguments Summary

### Server Arguments:

- `-server`: Run the program as a server.
- `-cert_file:<path_to_cert_file>`: Path to the server's SSL certificate file (e.g., `certificates/server.crt`).
- `-key_file:<path_to_key_file>`: Path to the server's private key file (e.g., `certificates/server.key`).

### Client Arguments:

- `-client`: Run the program as a client.
- `-target:<ipAddr>:<port>`: Target server IP address and port.
- `-unsecure`: Use an unencrypted connection.
- `requests:<path_to_requests_file>`: Path to a file containing HTTP requests. The file should contain a list of HTTP requests with optional Body: sections, as shown above.
