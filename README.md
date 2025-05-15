# go-pqc-tls

A Go implementation of a hybrid cryptographic system combining classical (ECDH) and post-quantum cryptography (PQC) for secure communication over both TLS and UDP protocols.

## Project Structure

- `peer/main.go`: Main peer-to-peer chat application with hybrid encryption (ECDH + PQC)
- `server/`: TLS server implementation
- `client/`: TLS client implementation
- `cmd/`: Command-line tools
  - `sender/`: UDP hybrid sender implementation
  - `receiver/`: UDP hybrid receiver implementation

## Prerequisites

- Go 1.16 or later
- Required Go packages (automatically installed via `go mod`):
  - `golang.org/x/crypto/kyber`
  - `crypto/tls`
  - `crypto/ecdsa`
  - `crypto/elliptic`
  - `crypto/rand`

## Running the Applications

### 1. Peer-to-Peer Chat with Hybrid Encryption

The peer application implements a hybrid encryption scheme combining ECDH (classical) and post-quantum cryptography. After connecting, you can use the following commands in the chat interface:

- `sendfile <path>`: Send a file to all connected peers
- `help`: Display available commands
- `exit`: Close the connection and exit
- Regular text messages are sent to all connected peers

#### Pure ECDH Mode (Classical Only)
```bash
# Terminal 1
go run peer/main.go -listen :4433

# Terminal 2
go run peer/main.go -listen :4434 -connect "localhost:4433"
```

#### Hybrid ECDH + Kyber Mode
```bash
# Terminal 1
go run peer/main.go -listen :4433 -pqc kyber

# Terminal 2
go run peer/main.go -listen :4434 -connect "localhost:4433" -pqc kyber
```

#### Hybrid ECDH + Frodo Mode
```bash
# Terminal 1
go run peer/main.go -listen :4433 -pqc frodo

# Terminal 2
go run peer/main.go -listen :4434 -connect "localhost:4433" -pqc frodo
```

#### Hybrid ECDH + ML-KEM Mode
```bash
# Terminal 1
go run peer/main.go -listen :4433 -pqc mlkem

# Terminal 2
go run peer/main.go -listen :4434 -connect "localhost:4433" -pqc mlkem
```

### 2. UDP Hybrid Sender/Receiver

The UDP implementation provides a lightweight alternative for secure communication using hybrid encryption:

#### Running the Receiver
```bash
# Start the receiver on port 8080
go run cmd/receiver/main.go -port 8080
```

#### Running the Sender
```bash
# Send a message to the receiver
go run cmd/sender/main.go -addr localhost:8080 -message "Hello, secure UDP!"

# Send a file to the receiver
go run cmd/sender/main.go -addr localhost:8080 -file /path/to/your/file.txt
```

### 3. TLS Server-Client Example

```bash
# Terminal 1 - Start the server
go run server/main.go

# Terminal 2 - Start the client
go run client/main.go

# Send a file using TLS
go run client/main.go -file /path/to/your/file.txt
```

### 4. Multi-Peer Chat Example

To create a network of three peers with hybrid encryption:

```bash
# Terminal 1
go run peer/main.go -listen :4433 -connect "localhost:4434,localhost:4435" -pqc kyber

# Terminal 2
go run peer/main.go -listen :4434 -connect "localhost:4433,localhost:4435" -pqc kyber

# Terminal 3
go run peer/main.go -listen :4435 -connect "localhost:4433,localhost:4434" -pqc kyber
```

## Traffic Analysis with Wireshark

### TLS Traffic (Peer-to-Peer and Server-Client)
```bash
# Filter for TLS traffic on port 4433
tcp.port == 4433 and tls

# Filter for specific TLS handshake messages
tcp.port == 4433 and tls.handshake.type == 1  # Client Hello
tcp.port == 4433 and tls.handshake.type == 2  # Server Hello
tcp.port == 4433 and tls.handshake.type == 11 # Certificate
tcp.port == 4433 and tls.handshake.type == 16 # Client Key Exchange

# Filter for application data
tcp.port == 4433 and tls.record.content_type == 23
```

### UDP Traffic (Sender/Receiver)
```bash
# Filter for UDP traffic on port 8080
udp.port == 8080

# Filter for specific UDP packets
udp.port == 8080 and udp.length > 0  # Non-empty UDP packets
```

### Step-by-Step Analysis

1. **TLS Handshake Analysis**:
   ```bash
   # Start capture before running the application
   # Filter for the complete handshake
   tcp.port == 4433 and tls.handshake
   
   # Then analyze each step:
   tcp.port == 4433 and tls.handshake.type == 1  # Client Hello
   tcp.port == 4433 and tls.handshake.type == 2  # Server Hello
   tcp.port == 4433 and tls.handshake.type == 11 # Certificate
   tcp.port == 4433 and tls.handshake.type == 16 # Client Key Exchange
   ```

2. **File Transfer Analysis**:
   ```bash
   # For TLS file transfer
   tcp.port == 4433 and tls.record.content_type == 23 and tcp.len > 1000
   
   # For UDP file transfer
   udp.port == 8080 and udp.length > 1000
   ```

3. **Chat Message Analysis**:
   ```bash
   # For TLS chat messages
   tcp.port == 4433 and tls.record.content_type == 23 and tcp.len < 1000
   
   # For UDP chat messages
   udp.port == 8080 and udp.length < 1000
   ```

### Tips for Analysis

1. Start Wireshark before running any application
2. Use the filters above to focus on specific traffic types
3. For TLS traffic, you can see the handshake process but not the encrypted content
4. For UDP traffic, you can see packet sizes and timing
5. Use the "Follow TCP Stream" feature for TLS connections to see the complete conversation
6. Use the "Statistics" menu to analyze packet sizes and timing

## File Transfer Capabilities

### Peer-to-Peer File Transfer
In the peer-to-peer chat interface, you can transfer files using the following commands:
```bash
# After connecting to peers, use the chat interface:
sendfile /path/to/your/file.txt  # Sends file to all connected peers
```

Features:
- Files are automatically encrypted using the hybrid encryption scheme
- Progress is shown during file transfer
- Files are automatically chunked for large transfers
- Integrity verification using SHA-256
- Support for any file type

### TLS File Transfer
The TLS implementation supports secure file transfer with the following features:
- Automatic file chunking for large files
- Progress tracking during transfer
- Integrity verification using SHA-256
- Automatic reconnection on network issues
- Support for any file type

Example usage:
```bash
# Server side (receiving files)
go run server/main.go -receive-dir /path/to/receive/directory

# Client side (sending files)
go run client/main.go -file /path/to/send/file.txt
```

### UDP File Transfer
The UDP implementation provides lightweight file transfer capabilities:
- Optimized for smaller files
- Low overhead transfer
- Quick setup and teardown
- Support for multiple files in sequence

Example usage:
```bash
# Receiver side
go run cmd/receiver/main.go -port 8080 -receive-dir /path/to/receive/directory

# Sender side
go run cmd/sender/main.go -addr localhost:8080 -file /path/to/send/file.txt
```

## Security Features

### Hybrid Encryption Implementation

The system implements a hybrid encryption scheme that combines:

1. **Classical Cryptography (ECDH)**
   - Elliptic Curve Diffie-Hellman key exchange
   - P-256 curve for key generation
   - Provides forward secrecy through ephemeral key pairs

2. **Post-Quantum Cryptography (PQC)**
   - Supports multiple PQC algorithms:
     - Kyber-512: Lattice-based KEM
     - Frodo: LWE-based KEM
     - ML-KEM: Module Lattice-based KEM
   - Provides quantum resistance

3. **Hybrid Key Derivation**
   - Combines ECDH and PQC shared secrets
   - Uses SHA3-256 for key derivation
   - Provides both classical and quantum security

4. **Symmetric Encryption**
   - AES-GCM for message encryption
   - Provides authenticated encryption

### Protocol Support

1. **TLS Protocol**
   - Secure TCP-based communication
   - Self-signed certificates for authentication
   - Full TLS handshake with hybrid key exchange

2. **UDP Protocol**
   - Lightweight secure communication
   - Hybrid encryption for message security
   - No connection establishment overhead

## Docker Support

You can also run the peer application using Docker:

```bash
# Build the Docker image
docker build -t peer-tls .

# Run the peer
docker run -it --rm -p 4433:4433 peer-tls -listen :4433

# For ARM64 architecture
docker run -it --rm -p 4433:4433 peer-chat:arm64 -listen :4433
```

## Notes

- The server uses a self-signed certificate for TLS
- Default port is 4433, but you can specify different ports
- The peer application supports multiple post-quantum algorithms
- UDP implementation provides a lightweight alternative to TLS
- All cryptographic operations use Go's standard crypto packages and the Kyber implementation
- File transfers are automatically encrypted using the hybrid encryption scheme
- Large files are automatically chunked and reassembled during transfer
- In peer-to-peer chat, use `sendfile <path>` command to transfer files
