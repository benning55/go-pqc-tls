package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"golang.org/x/crypto/sha3"
)

func main() {
	config := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "localhost:4433", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// ECDH Key Exchange
	curve := ecdh.P256()
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("❌ ECDH Error:", err)
		return
	}
	clientPub := clientPriv.PublicKey().Bytes()
	serverPubBytes := make([]byte, 65)
	_, err = conn.Read(serverPubBytes)
	if err != nil {
		fmt.Println("❌ Failed to receive ECDH key:", err)
		return
	}
	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		fmt.Println("❌ Invalid server public key:", err)
		return
	}
	ecdhSharedKey, err := clientPriv.ECDH(serverPub)
	if err != nil {
		fmt.Println("❌ ECDH computation failed:", err)
		return
	}
	_, err = conn.Write(clientPub)
	if err != nil {
		fmt.Println("❌ Failed to send ECDH key:", err)
		return
	}

	// Kyber-512 KEM
	sch := kyber512.Scheme()
	kyberPubBytes := make([]byte, kyber512.PublicKeySize) // 768 bytes
	_, err = conn.Read(kyberPubBytes)
	if err != nil {
		fmt.Println("❌ Failed to receive Kyber public key:", err)
		return
	}
	kyberPub, err := sch.UnmarshalBinaryPublicKey(kyberPubBytes)
	if err != nil {
		fmt.Println("❌ Invalid Kyber public key:", err)
		return
	}
	kyberCiphertext, kyberShared, err := sch.Encapsulate(kyberPub)
	if err != nil {
		fmt.Println("❌ Kyber encapsulation failed:", err)
		return
	}
	_, err = conn.Write(kyberCiphertext)
	if err != nil {
		fmt.Println("❌ Failed to send Kyber ciphertext:", err)
		return
	}

	// Hybrid Key: Concatenate ECDH + Kyber, then hash
	hasher := sha3.New256()
	hasher.Write(ecdhSharedKey)
	hasher.Write(kyberShared)
	hybridKey := hasher.Sum(nil)
	fmt.Println("✅ Client Hybrid Key:", hybridKey)

	// Decrypt server message
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("❌ Failed to read encrypted message:", err)
		return
	}
	ciphertext := buffer[:n]
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
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("❌ Decryption failed:", err)
		return
	}
	fmt.Println("📩 Server:", string(plaintext))
}
