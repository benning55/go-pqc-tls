# go-pqc-tls

# Project Overview

This project implements a hybrid cryptographic system combining ECDH (classical) and Kyber-512 (post-quantum) key exchanges to derive a shared symmetric key, used for AES-GCM encrypted communication over a TLS connection.


## Server (server.go)
- Purpose: Acts as the secure communication endpoint.
- Actions:
  - Sets up a TLS server on port 4433 with a self-signed certificate.
  - Performs ECDH and Kyber-512 key exchanges with the client.
  - Derives a hybrid key from both exchanges using SHA3-256.
  - Encrypts "Hello from server!" with AES-GCM and sends it to the client.


## Client (client.go)
- Purpose: Connects to the server and verifies secure communication.
- Actions:
  - Establishes a TLS connection to localhost:4433.
  - Completes ECDH and Kyber-512 key exchanges with the server.
  - Derives the same hybrid key using SHA3-256.
  - Receives, decrypts, and displays the server’s encrypted message.


## Peer (peer.go)

`peer.go` creates a network of chat peers that:
- **Listen** for incoming connections on a specified port (e.g., `:4433`).
- **Connect** to other peers via a configurable list (e.g., `localhost:4434,localhost:4435`).
- **Encrypt and Send** messages securely to all connected peers.
- **Receive and Decrypt** messages, displaying them with timestamps in a polished format.

You start three apps:
./bin/peer -listen :4433 -connect "localhost:4434,localhost:4435"
./bin/peer -listen :4434 -connect "localhost:4433,localhost:4435"
./bin/peer -listen :4435 -connect "localhost:4433,localhost:4434"


### How It Works

#### Program Structure

#### Main Setup
- Parses flags and initializes a `peers` map to track connections.
- Launches a listener and connects to peers concurrently.
- Waits up to 30 seconds for all peers to join before starting the chat.

#### Networking
- **`startListener`**: Runs a TCP server, accepting connections and spawning `handleIncoming` goroutines.
- **`connectToPeer`**: Dials peers with a 2-second retry loop, timing out after 30 seconds.
- **`handleIncoming`**: Processes incoming connections, avoiding duplicates in the `peers` map.

#### Chat Logic
- **`chatLoop`**: Reads input with `bufio.Scanner`, sends non-empty messages to peers, and echoes them locally.
- **`receiveMessages`**: Listens for incoming encrypted messages, decrypts them, and displays them with timestamps.

#### Encryption
- **`establishConnection`**: Sets up a secure channel per peer using hybrid encryption.

### Peer Management

- **Data Structure**: A `map[string]*Peer` (`peers`) stores each peer’s connection and encryption details.
- **Thread Safety**: Protected by `peersMu` (`sync.Mutex`) to handle concurrent access.

---

### Security: Hybrid Encryption Deep Dive

`peer.go` uses a **hybrid encryption** scheme that blends asymmetric and symmetric cryptography for maximum security. Here’s how it keeps your chats safe:

#### 1. Authentication with ECDSA
- **Tech**: Elliptic Curve Digital Signature Algorithm (P-256 curve).
- **Process**:
  - Each peer has a static ECDSA key pair (`privKey`).
  - Server sends its public key and signs a challenge (client’s port).
  - Client sends a challenge and receives the signature.
- **Security**: Lays the groundwork for identity verification (though not fully enforced—see weaknesses).

#### 2. Key Exchange
- **ECDH (Elliptic Curve Diffie-Hellman)**:
  - Generates a fresh P-256 key pair per connection.
  - Exchanges public keys to compute a shared secret (`ecdhSharedKey`).
  - **Benefit**: Forward secrecy—past sessions stay secure if a key leaks later.
- **Kyber-512 (Post-Quantum KEM)**:
  - Server generates a Kyber key pair, client encapsulates a secret.
  - Both derive the same `kyberShared` secret.
  - **Benefit**: Quantum resistance—safe against future quantum attacks.

#### 3. Hybrid Key Derivation
- **Method**: Combines `ecdhSharedKey` and `kyberShared` with SHA3-256:
  ```go
  hasher := sha3.New256()
  hasher.Write(ecdhSharedKey)
  hasher.Write(kyberShared)
  hybridKey := hasher.Sum(nil)


#### 4. Run via docker
  ```go
  docker build -t peer-tls .
  docker run -it --rm -p 4433:4433 peer-tls -listen :4433
  docker run -it --rm -p 4433:4433 peer-chat:arm64 -listen :4433