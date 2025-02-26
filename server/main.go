package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"golang.org/x/crypto/sha3"
)

func main() {
	certPEM, keyPEM := loadOrGenerateCertificate()
	certPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		MinVersion:   tls.VersionTLS13,
	}
	listener, err := tls.Listen("tcp", ":4433", config)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("✅ Hybrid TLS Server Running on port 4433...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("❌ Connection failed:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// ECDH Key Exchange
	curve := ecdh.P256()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("❌ ECDH Error:", err)
		return
	}
	serverPub := serverPriv.PublicKey().Bytes()
	_, err = conn.Write(serverPub)
	if err != nil {
		fmt.Println("❌ Failed to send ECDH key:", err)
		return
	}

	clientPubBytes := make([]byte, 65)
	_, err = conn.Read(clientPubBytes)
	if err != nil {
		fmt.Println("❌ Failed to receive ECDH key:", err)
		return
	}
	clientPub, err := curve.NewPublicKey(clientPubBytes)
	if err != nil {
		fmt.Println("❌ Invalid client public key:", err)
		return
	}
	ecdhSharedKey, err := serverPriv.ECDH(clientPub)
	if err != nil {
		fmt.Println("❌ ECDH computation failed:", err)
		return
	}

	// Kyber-512 KEM
	sch := kyber512.Scheme()
	kyberPub, kyberPriv, err := sch.GenerateKeyPair()
	if err != nil {
		fmt.Println("❌ Kyber key generation failed:", err)
		return
	}
	kyberPubBytes, _ := kyberPub.MarshalBinary() // 768 bytes
	_, err = conn.Write(kyberPubBytes)
	if err != nil {
		fmt.Println("❌ Failed to send Kyber public key:", err)
		return
	}

	kyberCiphertext := make([]byte, kyber512.CiphertextSize) // 1088 bytes
	_, err = conn.Read(kyberCiphertext)
	if err != nil {
		fmt.Println("❌ Failed to receive Kyber ciphertext:", err)
		return
	}
	kyberShared, err := sch.Decapsulate(kyberPriv, kyberCiphertext[:kyber512.CiphertextSize])
	if err != nil {
		fmt.Println("❌ Kyber decapsulation failed:", err)
		return
	}

	// Hybrid Key: Concatenate ECDH + Kyber, then hash
	hasher := sha3.New256()
	hasher.Write(ecdhSharedKey)
	hasher.Write(kyberShared)
	hybridKey := hasher.Sum(nil)
	fmt.Println("✅ Server Hybrid Key:", hybridKey)

	// Encrypt and send a message
	block, err := aes.NewCipher(hybridKey)
	if err != nil {
		fmt.Println("❌ AES key setup failed:", err)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("❌ GCM setup failed:", err)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	plaintext := []byte("Hello from server!")
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	_, err = conn.Write(ciphertext)
	if err != nil {
		fmt.Println("❌ Failed to send encrypted message:", err)
	}
}

func loadOrGenerateCertificate() (certPEM, keyPEM []byte) {
	if _, err := os.Stat("server_cert.pem"); err == nil {
		certPEM, _ = os.ReadFile("server_cert.pem")
		keyPEM, _ = os.ReadFile("server_key.pem")
		return certPEM, keyPEM
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Hybrid TLS Server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	os.WriteFile("server_cert.pem", certPEM, 0644)
	os.WriteFile("server_key.pem", keyPEM, 0644)
	return certPEM, keyPEM
}
