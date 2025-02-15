# HTTP Server

This is a simple HTTP server implementation with SSL/TLS support using OpenSSL, `ls-qpack`, and `msquic`. It includes both server and client functionalities.

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

  - **Linux**: `sudo apt-get install openssl libssl-dev`
  - **macOS**: `brew install openssl`

- **CMake**: For building external libraries.

  - **Linux**: `sudo apt-get install cmake`
  - **macOS**: `brew install cmake`

- **Make**: For building the project.

  - **Linux**: `sudo apt-get install make`
  - **macOS**: `brew install make`

- **Git**: To clone the repository.
  - **Linux**: `sudo apt-get install git`
  - **macOS**: `brew install git`

This project depends on two external libraries:

- **ls-qpack** (a library for HTTP/2 compression)
- **msquic** (Microsoft's QUIC implementation)

When you clone the repository, the Makefile will attempt to clone these libraries and build them automatically.

## Build

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/http_server.git
cd http_server
```

### 2. Build the dependencies

```bash
make dependencies
```

### 3. Generate SSL Certificates

You need to generate SSL certificates for the server. Use OpenSSL to generate the certificate and private key:

```bash
mkdir certificates

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

Body: It's me Mario

GET /goodbye HTTP/1.1
Host: qqueke
User-Agent: custom-client/1.0
Accept: */*

Body: Goodbye, World!
```

**Note**: Client is used to perform HTTP3 requests for now. It will support HTTP1 and HTTP2 requests in the future.

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
