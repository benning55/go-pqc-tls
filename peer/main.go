package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"golang.org/x/crypto/sha3"
)

const (
	authTimeout    = 5 * time.Second
	msgTimeout     = 10 * time.Second
	reconnectDelay = 2 * time.Second
	maxConnectTime = 30 * time.Second
)

var privKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

type Peer struct {
	conn      net.Conn
	gcm       cipher.AEAD
	hybridKey []byte
	addr      string // Always ":port" (e.g., ":4433")
	localPort string
}

var (
	peers   = make(map[string]*Peer)
	peersMu sync.Mutex
)

func main() {
	listenPort := flag.String("listen", ":4433", "Port to listen on")
	connectAddrs := flag.String("connect", "localhost:4434", "Comma-separated addresses to connect to")
	flag.Parse()

	connectList := splitAddrs(*connectAddrs)

	// Start listener
	fmt.Printf("[INFO] Starting chat on %s...\n", *listenPort)
	go startListener(*listenPort)
	time.Sleep(500 * time.Millisecond)

	// Connect to all peers
	fmt.Println("[INFO] Connecting to peers...")
	var connectWg sync.WaitGroup
	for _, addr := range connectList {
		connectWg.Add(1)
		go func(addr string) {
			defer connectWg.Done()
			connectToPeer(addr, *listenPort)
		}(addr)
	}
	connectWg.Wait()

	// Wait for all unique peers
	timeout := time.After(maxConnectTime)
	for {
		peersMu.Lock()
		uniquePeers := len(peers)
		peersMu.Unlock()
		if uniquePeers >= len(connectList) {
			break
		}
		select {
		case <-timeout:
			fmt.Printf("[ERROR] Timeout waiting for %d peers (got %d).\n", len(connectList), uniquePeers)
			os.Exit(1)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Start chatting
	peersMu.Lock()
	fmt.Printf("[INFO] Chat ready! Connected to %d peers.\n", len(peers))
	peersMu.Unlock()
	fmt.Println("-----------------------------------")
	chatLoop(*listenPort)
}

func splitAddrs(addrs string) []string {
	if addrs == "" {
		return nil
	}
	return strings.Split(addrs, ",")
}

func startListener(port string) {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Printf("[ERROR] Failed to listen on %s: %v\n", port, err)
		return
	}
	defer listener.Close()
	fmt.Printf("[INFO] Listening on %s\n", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("[ERROR] Accept failed: %v\n", err)
			continue
		}
		go handleIncoming(conn, port)
	}
}

func connectToPeer(addr, localPort string) {
	startTime := time.Now()
	for {
		if time.Since(startTime) > maxConnectTime {
			fmt.Printf("[ERROR] Timeout connecting to %s after %v\n", addr, maxConnectTime)
			return
		}
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Printf("[WARN] Failed to connect to %s: %v, retrying in %v\n", addr, err, reconnectDelay)
			time.Sleep(reconnectDelay)
			continue
		}
		peer, err := establishConnection(conn, false, localPort, addr)
		if err != nil {
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}
		peersMu.Lock()
		if _, exists := peers[peer.addr]; !exists {
			peers[peer.addr] = peer
			fmt.Printf("[INFO] Connected to %s\n", peer.addr)
			go receiveMessages(peer, localPort)
		}
		peersMu.Unlock()
		return
	}
}

func handleIncoming(conn net.Conn, localPort string) {
	peer, err := establishConnection(conn, true, localPort, "")
	if err != nil {
		conn.Close()
		return
	}
	peersMu.Lock()
	if _, exists := peers[peer.addr]; !exists {
		peers[peer.addr] = peer
		fmt.Printf("[INFO] Accepted connection from %s\n", peer.addr)
		go receiveMessages(peer, localPort)
	}
	peersMu.Unlock()
}

func establishConnection(conn net.Conn, isServer bool, localPort, remoteAddr string) (*Peer, error) {
	conn.SetDeadline(time.Now().Add(authTimeout))
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	var intendedRemote string
	if isServer {
		binary.Write(conn, binary.BigEndian, uint32(len(pubKeyBytes)))
		conn.Write(pubKeyBytes)
		var challengeLen uint32
		binary.Read(conn, binary.BigEndian, &challengeLen)
		challenge := make([]byte, challengeLen)
		conn.Read(challenge)
		var sigLen uint32
		binary.Read(conn, binary.BigEndian, &sigLen)
		sig := make([]byte, sigLen)
		conn.Read(sig)
		intendedRemote = string(challenge) // e.g., ":4433"
	} else {
		var pubKeyLen uint32
		binary.Read(conn, binary.BigEndian, &pubKeyLen)
		pubKeyBytes := make([]byte, pubKeyLen)
		conn.Read(pubKeyBytes)
		challenge := []byte(localPort)
		binary.Write(conn, binary.BigEndian, uint32(len(challenge)))
		conn.Write(challenge)
		sig, _ := ecdsa.SignASN1(rand.Reader, privKey, challenge)
		binary.Write(conn, binary.BigEndian, uint32(len(sig)))
		conn.Write(sig)
		_, port, _ := net.SplitHostPort(remoteAddr)
		intendedRemote = ":" + port // Normalize to ":4434"
	}

	curve := ecdh.P256()
	localPriv, _ := curve.GenerateKey(rand.Reader)
	localPub := localPriv.PublicKey().Bytes()
	remotePub := make([]byte, 65)
	if isServer {
		conn.Write(localPub)
		conn.Read(remotePub)
	} else {
		conn.Read(remotePub)
		conn.Write(localPub)
	}
	remotePubKey, _ := curve.NewPublicKey(remotePub)
	ecdhSharedKey, _ := localPriv.ECDH(remotePubKey)

	sch := kyber512.Scheme()
	var kyberShared []byte
	if isServer {
		kyberPub, kyberPriv, _ := sch.GenerateKeyPair()
		kyberPubBytes, _ := kyberPub.MarshalBinary()
		conn.Write(kyberPubBytes)
		kyberCiphertext := make([]byte, kyber512.CiphertextSize)
		conn.Read(kyberCiphertext)
		kyberShared, _ = sch.Decapsulate(kyberPriv, kyberCiphertext)
	} else {
		kyberPubBytes := make([]byte, kyber512.PublicKeySize)
		conn.Read(kyberPubBytes)
		kyberPub, _ := sch.UnmarshalBinaryPublicKey(kyberPubBytes)
		kyberCiphertext, kyberSharedTemp, _ := sch.Encapsulate(kyberPub)
		conn.Write(kyberCiphertext)
		kyberShared = kyberSharedTemp
	}

	hasher := sha3.New256()
	hasher.Write(ecdhSharedKey)
	hasher.Write(kyberShared)
	hybridKey := hasher.Sum(nil)

	block, _ := aes.NewCipher(hybridKey)
	gcm, _ := cipher.NewGCM(block)
	return &Peer{conn: conn, gcm: gcm, hybridKey: hybridKey, addr: intendedRemote, localPort: localPort}, nil
}

func receiveMessages(peer *Peer, localPort string) {
	conn := peer.conn
	gcm := peer.gcm
	conn.SetDeadline(time.Time{})
	for {
		var length uint32
		err := binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			fmt.Printf("\n[ERROR] Connection to %s closed: %v\n", peer.addr, err)
			peersMu.Lock()
			delete(peers, peer.addr)
			peersMu.Unlock()
			conn.Close()
			fmt.Printf("[%s] You%s> ", time.Now().Format("15:04:05"), localPort)
			return
		}
		data := make([]byte, length)
		_, err = conn.Read(data)
		if err != nil {
			fmt.Printf("\n[ERROR] Connection to %s closed: %v\n", peer.addr, err)
			peersMu.Lock()
			delete(peers, peer.addr)
			peersMu.Unlock()
			conn.Close()
			fmt.Printf("[%s] You%s> ", time.Now().Format("15:04:05"), localPort)
			return
		}
		ciphertext := data
		nonceSize := gcm.NonceSize()
		nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
		if err != nil {
			fmt.Printf("\n[ERROR] Decryption failed: %v\n", err)
			fmt.Printf("[%s] You%s> ", time.Now().Format("15:04:05"), localPort)
			return
		}
		msg := string(plaintext)
		fmt.Printf("\n[%s] %s: %s\n", time.Now().Format("15:04:05"), peer.addr, msg)
		fmt.Printf("[%s] You%s> ", time.Now().Format("15:04:05"), localPort)
	}
}

func chatLoop(listenPort string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("[%s] You%s> ", time.Now().Format("15:04:05"), listenPort)
		scanner.Scan()
		msg := scanner.Text()
		if msg == "exit" {
			peersMu.Lock()
			for _, peer := range peers {
				peer.conn.Close()
			}
			peersMu.Unlock()
			fmt.Println("\n[INFO] Goodbye!")
			os.Exit(0)
		}
		// Always start on a new line after input
		fmt.Println()
		if msg != "" {
			peersMu.Lock()
			// timestamp := time.Now().Format("15:04:05")
			// fmt.Println("")
			// fmt.Printf("[%s] You%s> %s\n", timestamp, listenPort, msg)
			for _, peer := range peers {
				conn := peer.conn
				gcm := peer.gcm
				conn.SetWriteDeadline(time.Now().Add(msgTimeout))
				nonce := make([]byte, gcm.NonceSize())
				rand.Read(nonce)
				ciphertext := gcm.Seal(nonce, nonce, []byte(msg), nil)
				binary.Write(conn, binary.BigEndian, uint32(len(ciphertext)))
				conn.Write(ciphertext)
			}
			peersMu.Unlock()
		}
		// Fresh prompt on a new line
		// fmt.Printf("[%s] You%s> ", time.Now().Format("15:04:05"), listenPort)
	}
}
