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
	fmt.Println("Establishing TCP connection for key exchange...")
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
	kyberPubBytes := make([]byte, kyber512.PublicKeySize)
	if _, err := tcpConn.Read(kyberPubBytes); err != nil {
		fmt.Printf("Failed to receive Kyber public key: %v\n", err)
		os.Exit(1)
	}

	kyberPub, err := sch.UnmarshalBinaryPublicKey(kyberPubBytes)
	if err != nil {
		fmt.Printf("Invalid Kyber public key: %v\n", err)
		os.Exit(1)
	}

	kyberCiphertext, kyberShared, err := sch.Encapsulate(kyberPub)
	if err != nil {
		fmt.Printf("Failed Kyber encapsulation: %v\n", err)
		os.Exit(1)
	}

	if _, err := tcpConn.Write(kyberCiphertext); err != nil {
		fmt.Printf("Failed to send Kyber ciphertext: %v\n", err)
		os.Exit(1)
	}

	// Derive hybrid key
	hasher := sha3.New256()
	hasher.Write(ecdhSharedKey)
	hasher.Write(kyberShared)
	hybridKey := hasher.Sum(nil)

	// Create UDP peer with hybrid key and encryption log file
	fmt.Println("Creating UDP peer...")
	encryptLog, err := os.OpenFile("encrypt.json", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Failed to create encryption log file: %v\n", err)
		os.Exit(1)
	}
	defer encryptLog.Close()

	peer, err := udp.NewSimpleUDPPeer(*listenPort, hybridKey, encryptLog)
	if err != nil {
		fmt.Printf("Failed to create UDP peer: %v\n", err)
		os.Exit(1)
	}
	defer peer.Close()

	// Get file info
	fileInfo, err := os.Stat(*filePath)
	if err != nil {
		fmt.Printf("Failed to get file info: %v\n", err)
		os.Exit(1)
	}

	fileSize := fileInfo.Size()
	fmt.Printf("\nFile Transfer Statistics:\n")
	fmt.Printf("Machine Spec: 12th Gen Intel Core i7-1260P, 15GB RAM, 512GB NVMe SSD\n")
	fmt.Printf("File: %s\n", *filePath)
	fmt.Printf("Size: %d bytes (%.2f MB)\n", fileSize, float64(fileSize)/1024/1024)
	fmt.Printf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Protocol: UDP with ECDH + Kyber\n\n")

	// Send the file and record timing
	fmt.Println("Sending file...")
	startTime := time.Now()
	if err := peer.SendFile(*filePath, *remoteAddr); err != nil {
		fmt.Printf("Error sending file: %v\n", err)
		os.Exit(1)
	}
	totalTime := time.Since(startTime)

	fmt.Printf("\nTransfer Complete:\n")
	fmt.Printf("Total Time: %.3f seconds\n", totalTime.Seconds())
	fmt.Printf("Average Speed: %.2f MB/s\n", float64(fileSize)/1024/1024/totalTime.Seconds())
	fmt.Printf("Encryption metrics logged to: encrypt.json\n")
}
