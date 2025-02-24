package main

import (
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
	"time"

	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/util/random"
	"golang.org/x/crypto/sha3"
)

func main() {
	// Generate self-signed EC certificate
	certPEM, keyPEM := generateSelfSignedCert()

	// Load certificate properly
	certPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{certPair},
	}

	listener, err := tls.Listen("tcp", ":4433", config)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("Hybrid TLS Server Running on port 4433...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Connection failed:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// **Step 1: Perform ECDH Key Exchange**
	curve := elliptic.P256()
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader) // ✅ Removed unused `priv`
	if err != nil {
		fmt.Println("ECDH Error:", err)
		return
	}
	ecdhSharedKey := fmt.Sprintf("%x%x", x, y)

	// **Step 2: Perform Kyber Key Encapsulation**
	suite := edwards25519.NewBlakeSHA256Ed25519() // ✅ Correct function
	kyberSecret := suite.Scalar().Pick(random.New())

	// ✅ Serialize Kyber Scalar Correctly
	kyberBytes, _ := kyberSecret.MarshalBinary() // ✅ Corrected method

	// **Step 3: Hybrid Key Derivation (ECDH + Kyber)**
	hasher := sha3.New256()
	hasher.Write([]byte(ecdhSharedKey)) // Add ECDH shared secret
	hasher.Write(kyberBytes)            // Add Kyber shared secret
	hybridKey := hasher.Sum(nil)        // Hash to create hybrid key

	fmt.Println("Hybrid Shared Key:", hybridKey)
	conn.Write([]byte("Kyber + ECDH Secured Connection Established\n"))
}

// **🔹 Generate a self-signed EC certificate and return PEM data**
func generateSelfSignedCert() (certPEM, keyPEM []byte) {
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

	return certPEM, keyPEM
}
