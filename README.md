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