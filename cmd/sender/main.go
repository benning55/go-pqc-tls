package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/benning55/go-pqc-tls/pkg/udp"
)

func main() {
	// Parse command line arguments
	listenPort := flag.String("listen", ":0", "Port to listen on (default: random port)")
	remoteAddr := flag.String("remote", "", "Remote address to send file to (required)")
	filePath := flag.String("file", "", "File to send (required)")
	flag.Parse()

	// Validate required arguments
	if *remoteAddr == "" || *filePath == "" {
		fmt.Println("Error: -remote and -file are required")
		flag.Usage()
		os.Exit(1)
	}

	// First establish a TCP connection for key exchange
	tcpConn, err := net.Dial("tcp", *remoteAddr)
	if err != nil {
		fmt.Printf("Failed to establish TCP connection: %v\n", err)
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

	// Send our public key
	pubKey := privKey.PublicKey().Bytes()
	if _, err := tcpConn.Write(pubKey); err != nil {
		fmt.Printf("Failed to send public key: %v\n", err)
		os.Exit(1)
	}

	// Receive remote public key
	remotePubKey := make([]byte, 65)
	if _, err := tcpConn.Read(remotePubKey); err != nil {
		fmt.Printf("Failed to receive remote public key: %v\n", err)
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

	// Send the file
	fmt.Printf("Sending file %s to %s...\n", *filePath, *remoteAddr)
	if err := peer.SendFile(*filePath, *remoteAddr); err != nil {
		fmt.Printf("Failed to send file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("File sent successfully!")
}
