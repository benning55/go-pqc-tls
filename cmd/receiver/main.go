package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/benning55/go-pqc-tls/pkg/udp"
)

func main() {
	// Parse command line arguments
	listenPort := flag.String("listen", ":4433", "Port to listen on")
	outputDir := flag.String("output", ".", "Directory to save received files")
	flag.Parse()

	// Create TCP listener for key exchange
	tcpListener, err := net.Listen("tcp", *listenPort)
	if err != nil {
		fmt.Printf("Failed to listen on TCP port: %v\n", err)
		os.Exit(1)
	}
	defer tcpListener.Close()

	fmt.Printf("Waiting for key exchange on %s...\n", *listenPort)
	tcpConn, err := tcpListener.Accept()
	if err != nil {
		fmt.Printf("Failed to accept TCP connection: %v\n", err)
		os.Exit(1)
	}
	defer tcpConn.Close()

	// Perform ECDH key exchange
	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDH key: %v\n", err)
		os.Exit(1)
	}

	// Receive remote public key
	remotePubKey := make([]byte, 65)
	if _, err := tcpConn.Read(remotePubKey); err != nil {
		fmt.Printf("Failed to receive remote public key: %v\n", err)
		os.Exit(1)
	}

	// Send our public key
	pubKey := privKey.PublicKey().Bytes()
	if _, err := tcpConn.Write(pubKey); err != nil {
		fmt.Printf("Failed to send public key: %v\n", err)
		os.Exit(1)
	}

	// Compute shared secret
	remotePub, err := curve.NewPublicKey(remotePubKey)
	if err != nil {
		fmt.Printf("Invalid remote public key: %v\n", err)
		os.Exit(1)
	}

	sharedKey, err := privKey.ECDH(remotePub)
	if err != nil {
		fmt.Printf("Failed to compute shared secret: %v\n", err)
		os.Exit(1)
	}

	// Create UDP peer with shared key
	peer, err := udp.NewSimpleUDPPeer(*listenPort, sharedKey)
	if err != nil {
		fmt.Printf("Failed to create UDP peer: %v\n", err)
		os.Exit(1)
	}
	defer peer.Close()

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Start listening for incoming files
	fmt.Printf("Listening on %s for incoming files...\n", *listenPort)

	// Create a temporary file to receive the data
	tempFile := filepath.Join(*outputDir, "received_file")
	if err := peer.ReceiveFile(tempFile); err != nil {
		fmt.Printf("Failed to receive file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File received and saved as: %s\n", tempFile)
}
