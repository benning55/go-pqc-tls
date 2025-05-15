package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/benning55/go-pqc-tls/pkg/udp"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"golang.org/x/crypto/sha3"
)

func main() {
	// Parse command line arguments
	listenPort := flag.String("listen", ":4433", "Port to listen on")
	outputDir := flag.String("output", ".", "Directory to save received files")
	flag.Parse()

	// Create TCP listener for key exchange
	fmt.Printf("Waiting for key exchange on %s...\n", *listenPort)
	tcpListener, err := net.Listen("tcp", *listenPort)
	if err != nil {
		fmt.Printf("Failed to listen on TCP port: %v\n", err)
		os.Exit(1)
	}
	defer tcpListener.Close()

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

	// Compute ECDH shared secret
	remotePub, err := curve.NewPublicKey(remotePubKey)
	if err != nil {
		fmt.Printf("Invalid remote public key: %v\n", err)
		os.Exit(1)
	}

	ecdhSharedKey, err := privKey.ECDH(remotePub)
	if err != nil {
		fmt.Printf("Failed to compute ECDH shared secret: %v\n", err)
		os.Exit(1)
	}

	// Perform Kyber key exchange
	sch := kyber512.Scheme()
	kyberPub, kyberPriv, err := sch.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Kyber key generation failed: %v\n", err)
		os.Exit(1)
	}

	kyberPubBytes, err := kyberPub.MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal Kyber public key: %v\n", err)
		os.Exit(1)
	}

	if _, err := tcpConn.Write(kyberPubBytes); err != nil {
		fmt.Printf("Failed to send Kyber public key: %v\n", err)
		os.Exit(1)
	}

	kyberCiphertext := make([]byte, kyber512.CiphertextSize)
	if _, err := tcpConn.Read(kyberCiphertext); err != nil {
		fmt.Printf("Failed to receive Kyber ciphertext: %v\n", err)
		os.Exit(1)
	}

	kyberShared, err := sch.Decapsulate(kyberPriv, kyberCiphertext)
	if err != nil {
		fmt.Printf("Kyber decapsulation failed: %v\n", err)
		os.Exit(1)
	}

	// Derive hybrid key
	hasher := sha3.New256()
	hasher.Write(ecdhSharedKey)
	hasher.Write(kyberShared)
	hybridKey := hasher.Sum(nil)

	// Create UDP peer with hybrid key and decryption log file
	fmt.Println("Creating UDP peer...")
	decryptLog, err := os.OpenFile("decrypt.json", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Failed to create decryption log file: %v\n", err)
		os.Exit(1)
	}
	defer decryptLog.Close()

	peer, err := udp.NewSimpleUDPPeer(*listenPort, hybridKey, decryptLog)
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

	// Receive the file
	fmt.Printf("Waiting to receive file in directory %s...\n", *outputDir)
	startTime := time.Now()
	if err := peer.ReceiveFile(*outputDir); err != nil {
		fmt.Printf("Failed to receive file: %v\n", err)
		os.Exit(1)
	}
	totalTime := time.Since(startTime)

	fmt.Printf("\nTransfer Complete:\n")
	fmt.Printf("Total Time: %.3f seconds\n", totalTime.Seconds())
	fmt.Printf("Decryption metrics logged to: decrypt.json\n")
}
