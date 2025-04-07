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
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/sha3"
)

const (
	authTimeout    = 5 * time.Second
	msgTimeout     = 10 * time.Second
	reconnectDelay = 2 * time.Second
	maxConnectTime = 30 * time.Second
	chunkSize      = 1024 * 1024 // 1MB chunks
)

var privKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// ANSI color codes for prettier logs
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
)

type Peer struct {
	conn      net.Conn
	gcm       cipher.AEAD
	hybridKey []byte
	addr      string
	localPort string
	pqcAlgo   string
}

type MessageHeader struct {
	Type        uint8
	ChunkID     uint32
	TotalChunks uint32
	MetadataLen uint16
	Metadata    string
}

var (
	peers         = make(map[string]*Peer)
	peersMu       sync.Mutex
	receivedFiles = make(map[string]map[uint32][]byte)
	filesMu       sync.Mutex
	testMode      bool
)

func runPerformanceTest(listenPort, pqcAlgo string, connectList []string) {
	listenerChan := make(chan net.Listener)
	go func() {
		listener, err := startListener(listenPort, pqcAlgo, true)
		if err != nil {
			fmt.Printf("%s[ERROR]%s Failed to start listener: %v\n", Red, Reset, err)
			return
		}
		listenerChan <- listener
	}()
	time.Sleep(500 * time.Millisecond)

	if len(connectList) > 0 {
		connectToPeer(connectList[0], listenPort, pqcAlgo)
	} else {
		fmt.Println("Need a peer to test! Use -connect.")
		return
	}

	time.Sleep(1 * time.Second)
	peersMu.Lock()
	if len(peers) == 0 {
		fmt.Println("No peers connected for test!")
		peersMu.Unlock()
		return
	}
	var peer *Peer
	for _, p := range peers {
		peer = p
		break
	}
	peersMu.Unlock()

	if peer == nil {
		fmt.Println("No valid peer found for test!")
		return
	}

	sizes := map[string]int{
		"Small":  100,
		"Medium": 10 * 1024,
		"Large":  1024 * 1024,
	}

	fmt.Printf("Key exchange stats in listener logs\n")

	for name, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		startEncrypt := time.Now()
		nonce := make([]byte, peer.gcm.NonceSize())
		rand.Read(nonce)
		ciphertext := peer.gcm.Seal(nonce, nonce, data, nil)
		encryptDuration := time.Since(startEncrypt)

		startDecrypt := time.Now()
		nonceSize := peer.gcm.NonceSize()
		_, err := peer.gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
		decryptDuration := time.Since(startDecrypt)

		if err != nil {
			fmt.Printf("%s: Decryption failed: %v\n", name, err)
			continue
		}

		encryptMs := float64(encryptDuration.Nanoseconds()) / 1e6
		decryptMs := float64(decryptDuration.Nanoseconds()) / 1e6
		sizeLabel := name
		if name == "Medium" {
			sizeLabel += " (10 KB)"
		} else if name == "Large" {
			sizeLabel += " (1 MB)"
		} else {
			sizeLabel += " (100 bytes)"
		}
		fmt.Printf("%-20s  Encrypt: %.3f ms, Decrypt: %.3f ms\n", sizeLabel+":", encryptMs, decryptMs)
	}

	peer.conn.Close()
	listener := <-listenerChan
	listener.Close()
	fmt.Printf("%s[INFO]%s Test completed for %s\n", Green, Reset, pqcAlgo)
}

func main() {
	listenPort := flag.String("listen", ":4433", "Port to listen on")
	connectAddrs := flag.String("connect", "", "Comma-separated addresses to connect to")
	pqcAlgo := flag.String("pqc", "", "Post-quantum key exchange algorithm (kyber, frodo, mlkem; empty for ECDH only)")
	flag.BoolVar(&testMode, "test", false, "Run performance test")
	flag.Parse()

	connectList := splitAddrs(*connectAddrs)

	if testMode {
		runPerformanceTest(*listenPort, *pqcAlgo, connectList)
		return
	}

	go startListener(*listenPort, *pqcAlgo, false)
	time.Sleep(500 * time.Millisecond)

	var connectWg sync.WaitGroup
	for _, addr := range connectList {
		connectWg.Add(1)
		go func(addr string) {
			defer connectWg.Done()
			connectToPeer(addr, *listenPort, *pqcAlgo)
		}(addr)
	}
	connectWg.Wait()

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
			fmt.Printf("%s[ERROR]%s Timeout waiting for %d peers (got %d).\n", Red, Reset, len(connectList), uniquePeers)
			os.Exit(1)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	peersMu.Lock()
	fmt.Printf("%s[INFO]%s Chat ready! Connected to %d peers.\n", Green, Reset, len(peers))
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

func startListener(port, pqcAlgo string, isTest bool) (net.Listener, error) {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Printf("%s[ERROR]%s Failed to listen on %s: %v\n", Red, Reset, port, err)
		return nil, err
	}
	fmt.Printf("%s[INFO]%s Listening on %s\n", Green, Reset, port)

	if isTest {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("%s[ERROR]%s Accept failed: %v\n", Red, Reset, err)
			return listener, err
		}
		go handleIncoming(conn, port, pqcAlgo)
		return listener, nil
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("%s[ERROR]%s Accept failed: %v\n", Red, Reset, err)
			continue
		}
		go handleIncoming(conn, port, pqcAlgo)
	}
}

func connectToPeer(addr, localPort, pqcAlgo string) {
	startTime := time.Now()
	for {
		if time.Since(startTime) > maxConnectTime {
			fmt.Printf("%s[ERROR]%s Timeout connecting to %s after %v\n", Red, Reset, addr, maxConnectTime)
			return
		}
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Printf("%s[WARN]%s Failed to connect to %s: %v, retrying in %v\n", Yellow, Reset, addr, err, reconnectDelay)
			time.Sleep(reconnectDelay)
			continue
		}
		peer, err := establishConnection(conn, false, localPort, addr, pqcAlgo)
		if err != nil {
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}
		peersMu.Lock()
		if _, exists := peers[peer.addr]; !exists {
			peers[peer.addr] = peer
			fmt.Printf("%s[INFO]%s Connected to %s\n", Green, Reset, peer.addr)
			if !testMode {
				go receiveMessages(peer, localPort)
			}
		}
		peersMu.Unlock()
		return
	}
}

func handleIncoming(conn net.Conn, localPort, pqcAlgo string) {
	peer, err := establishConnection(conn, true, localPort, "", pqcAlgo)
	if err != nil {
		conn.Close()
		return
	}
	peersMu.Lock()
	if _, exists := peers[peer.addr]; !exists {
		peers[peer.addr] = peer
		fmt.Printf("%s[INFO]%s Accepted connection from %s\n", Green, Reset, peer.addr)
		if !testMode {
			go receiveMessages(peer, localPort)
		}
	}
	peersMu.Unlock()
}

func getKEMScheme(pqcAlgo string) (kem.Scheme, error) {
	switch pqcAlgo {
	case "kyber":
		return kyber512.Scheme(), nil
	case "frodo":
		return frodo640shake.Scheme(), nil
	case "mlkem":
		return mlkem768.Scheme(), nil
	case "":
		return nil, nil // ECDH only
	default:
		return nil, fmt.Errorf("unsupported PQC algorithm: %s", pqcAlgo)
	}
}

func performPQCKeyExchange(conn net.Conn, isServer bool, scheme kem.Scheme) ([]byte, error) {
	if isServer {
		pk, sk, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, err = conn.Write(pkBytes)
		if err != nil {
			return nil, err
		}
		ciphertext := make([]byte, scheme.CiphertextSize())
		_, err = conn.Read(ciphertext)
		if err != nil {
			return nil, err
		}
		shared, err := scheme.Decapsulate(sk, ciphertext)
		if err != nil {
			return nil, err
		}
		return shared, nil
	} else {
		pkBytes := make([]byte, scheme.PublicKeySize())
		_, err := conn.Read(pkBytes)
		if err != nil {
			return nil, err
		}
		pk, err := scheme.UnmarshalBinaryPublicKey(pkBytes)
		if err != nil {
			return nil, err
		}
		ciphertext, shared, err := scheme.Encapsulate(pk)
		if err != nil {
			return nil, err
		}
		_, err = conn.Write(ciphertext)
		if err != nil {
			return nil, err
		}
		return shared, nil
	}
}

func establishConnection(conn net.Conn, isServer bool, localPort, remoteAddr, pqcAlgo string) (*Peer, error) {
	startTotal := time.Now()

	conn.SetDeadline(time.Now().Add(authTimeout))
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	var intendedRemote string

	var remotePqcAlgo string
	if isServer {
		binary.Write(conn, binary.BigEndian, uint32(len(pqcAlgo)))
		conn.Write([]byte(pqcAlgo))
		var pqcLen uint32
		binary.Read(conn, binary.BigEndian, &pqcLen)
		remotePqcBytes := make([]byte, pqcLen)
		conn.Read(remotePqcBytes)
		remotePqcAlgo = string(remotePqcBytes)
	} else {
		var pqcLen uint32
		binary.Read(conn, binary.BigEndian, &pqcLen)
		remotePqcBytes := make([]byte, pqcLen)
		conn.Read(remotePqcBytes)
		remotePqcAlgo = string(remotePqcBytes)
		binary.Write(conn, binary.BigEndian, uint32(len(pqcAlgo)))
		conn.Write([]byte(pqcAlgo))
	}

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
		intendedRemote = string(challenge)
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
		intendedRemote = ":" + port
	}

	startECDH := time.Now()
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
	ecdhDuration := time.Since(startECDH)

	var pqcShared []byte
	var pqcDuration time.Duration
	scheme, err := getKEMScheme(pqcAlgo)
	if err != nil {
		return nil, err
	}
	if pqcAlgo != "" && scheme != nil {
		startPQC := time.Now()
		pqcShared, err = performPQCKeyExchange(conn, isServer, scheme)
		if err != nil {
			return nil, fmt.Errorf("PQC key exchange failed: %v", err)
		}
		pqcDuration = time.Since(startPQC)
	}

	startHybrid := time.Now()
	hasher := sha3.New256()
	hasher.Write(ecdhSharedKey)
	if pqcShared != nil {
		hasher.Write(pqcShared)
	}
	hybridKey := hasher.Sum(nil)
	hybridDuration := time.Since(startHybrid)

	block, _ := aes.NewCipher(hybridKey)
	gcm, _ := cipher.NewGCM(block)

	totalDuration := time.Since(startTotal)

	totalMs := float64(totalDuration.Nanoseconds()) / 1e6
	ecdhMs := float64(ecdhDuration.Nanoseconds()) / 1e6
	hybridMs := float64(hybridDuration.Nanoseconds()) / 1e6
	if pqcAlgo == "" {
		fmt.Printf("%s[STATS]%s Key Exchange (ECDH only): Total: %.3f ms (ECDH: %.3f ms, Hybrid Derivation: %.3f ms)\n",
			Cyan, Reset, totalMs, ecdhMs, hybridMs)
	} else {
		pqcMs := float64(pqcDuration.Nanoseconds()) / 1e6
		pqcLabel := "PQC " + strings.Title(pqcAlgo)
		fmt.Printf("%s[STATS]%s Key Exchange (Hybrid): Total: %.3f ms (ECDH: %.3f ms, %s: %.3f ms, Hybrid Derivation: %.3f ms)\n",
			Cyan, Reset, totalMs, ecdhMs, pqcLabel, pqcMs, hybridMs)
	}

	if remotePqcAlgo != pqcAlgo {
		fmt.Printf("%s[WARN]%s PQC mismatch: local (%s) vs remote (%s). Communication may fail.\n",
			Yellow, Reset, pqcAlgo, remotePqcAlgo)
	}

	return &Peer{conn: conn, gcm: gcm, hybridKey: hybridKey, addr: intendedRemote, localPort: localPort, pqcAlgo: pqcAlgo}, nil
}

func receiveMessages(peer *Peer, localPort string) {
	conn := peer.conn
	gcm := peer.gcm
	conn.SetDeadline(time.Time{})
	reader := bufio.NewReader(conn)

	for {
		var length uint32
		err := binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			fmt.Printf("\n%s[ERROR]%s Connection to %s closed: %v\n", Red, Reset, peer.addr, err)
			peersMu.Lock()
			delete(peers, peer.addr)
			peersMu.Unlock()
			conn.Close()
			return
		}

		data := make([]byte, length)
		_, err = io.ReadFull(reader, data)
		if err != nil {
			fmt.Printf("\n%s[ERROR]%s Read failed: %v\n", Red, Reset, peer.addr, err)
			return
		}

		ciphertext := data
		nonceSize := gcm.NonceSize()
		nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]

		startDecrypt := time.Now()
		plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
		decryptDuration := time.Since(startDecrypt)
		if err != nil {
			fmt.Printf("\n%s[ERROR]%s Decryption failed (possible PQC mismatch with %s): %v\n", Red, Reset, peer.addr, err)
			return
		}
		decryptMs := float64(decryptDuration.Nanoseconds()) / 1e6
		fmt.Printf("%s[STATS]%s Decryption Time: %.3f ms\n", Cyan, Reset, decryptMs)

		header, payload, err := parseHeader(plaintext)
		if err != nil {
			fmt.Printf("\n%s[ERROR]%s Header parse failed: %v\n", Red, Reset, err)
			continue
		}

		if header.Type == 0 {
			fmt.Printf("\n%s[%s]%s %s%s%s: %s\n", Blue, time.Now().Format("15:04:05"), Reset, Green, peer.addr, Reset, string(payload))
		} else {
			handleFileChunk(peer.addr, header, payload)
		}
		fmt.Printf("%s[%s]%s You%s> ", Blue, time.Now().Format("15:04:05"), Reset, localPort)
	}
}

func parseHeader(data []byte) (MessageHeader, []byte, error) {
	if len(data) < 11 {
		return MessageHeader{}, nil, fmt.Errorf("data too short")
	}
	header := MessageHeader{
		Type:        data[0],
		ChunkID:     binary.BigEndian.Uint32(data[1:5]),
		TotalChunks: binary.BigEndian.Uint32(data[5:9]),
		MetadataLen: binary.BigEndian.Uint16(data[9:11]),
	}
	if len(data) < 11+int(header.MetadataLen) {
		return MessageHeader{}, nil, fmt.Errorf("metadata truncated")
	}
	header.Metadata = string(data[11 : 11+header.MetadataLen])
	payload := data[11+header.MetadataLen:]
	return header, payload, nil
}

func handleFileChunk(addr string, header MessageHeader, payload []byte) {
	filesMu.Lock()
	defer filesMu.Unlock()

	filename := header.Metadata
	if _, exists := receivedFiles[addr]; !exists {
		receivedFiles[addr] = make(map[uint32][]byte)
	}
	receivedFiles[addr][header.ChunkID] = payload

	if len(receivedFiles[addr]) == int(header.TotalChunks) {
		var fullData []byte
		for i := uint32(0); i < header.TotalChunks; i++ {
			fullData = append(fullData, receivedFiles[addr][i]...)
		}

		cwd, err := os.Getwd()
		if err != nil {
			fmt.Printf("%s[ERROR]%s Failed to get CWD: %v\n", Red, Reset, err)
			os.Exit(1)
		}
		baseFilename := filepath.Base(filename)
		savePath := filepath.Join(cwd, baseFilename)
		err = os.WriteFile(savePath, fullData, 0644)
		if err != nil {
			fmt.Printf("\n%s[ERROR]%s Failed to save %s: %v\n", Red, Reset, filename, err)
		} else {
			absPath, _ := filepath.Abs(savePath)
			fmt.Printf("\n%s[INFO]%s Received and saved file: %s from %s at %s\n", Green, Reset, baseFilename, addr, absPath)
		}
		delete(receivedFiles, addr)
	}
}

func chatLoop(listenPort string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s[%s]%s You%s> ", Blue, time.Now().Format("15:04:05"), Reset, listenPort)
		scanner.Scan()
		input := scanner.Text()

		if input == "exit" {
			peersMu.Lock()
			for _, peer := range peers {
				peer.conn.Close()
			}
			peersMu.Unlock()
			fmt.Printf("\n%s[INFO]%s Goodbye!\n", Green, Reset)
			os.Exit(0)
		}

		fmt.Println()
		if strings.HasPrefix(input, "sendfile ") {
			filename := strings.TrimPrefix(input, "sendfile ")
			err := sendFile(filename)
			if err != nil {
				fmt.Printf("%s[ERROR]%s Failed to send file: %v\n", Red, Reset, err)
			}
		} else if input != "" {
			sendTextMessage(input)
		}
	}
}

func sendTextMessage(msg string) {
	peersMu.Lock()
	defer peersMu.Unlock()

	header := MessageHeader{
		Type:        0,
		ChunkID:     0,
		TotalChunks: 1,
		MetadataLen: 0,
	}
	data := encodeHeader(header)
	data = append(data, []byte(msg)...)

	var totalEncryptTime time.Duration
	for _, peer := range peers {
		localPqc := peer.pqcAlgo
		if localPqc != peer.pqcAlgo {
			fmt.Printf("%s[WARN]%s Cannot send to %s: PQC mismatch (local: %s, remote: %s)\n",
				Yellow, Reset, peer.addr, localPqc, peer.pqcAlgo)
			continue
		}

		conn := peer.conn
		gcm := peer.gcm
		conn.SetWriteDeadline(time.Now().Add(msgTimeout))
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)

		startEncrypt := time.Now()
		ciphertext := gcm.Seal(nonce, nonce, data, nil)
		encryptDuration := time.Since(startEncrypt)
		totalEncryptTime += encryptDuration

		encryptMs := float64(encryptDuration.Nanoseconds()) / 1e6
		fmt.Printf("%s[STATS]%s Text Message Encryption to %s: %.3f ms\n", Cyan, Reset, peer.addr, encryptMs)

		err := binary.Write(conn, binary.BigEndian, uint32(len(ciphertext)))
		if err != nil {
			fmt.Printf("%s[ERROR]%s Failed to send length to %s: %v\n", Red, Reset, peer.addr, err)
			continue
		}
		_, err = conn.Write(ciphertext)
		if err != nil {
			fmt.Printf("%s[ERROR]%s Failed to send message to %s: %v\n", Red, Reset, peer.addr, err)
			continue
		}
	}
	totalEncryptMs := float64(totalEncryptTime.Nanoseconds()) / 1e6
	fmt.Printf("%s[STATS]%s Total Encryption Time for Text Message (%d bytes): %.3f ms\n", Cyan, Reset, len(data), totalEncryptMs)
}

func sendFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()
	totalChunks := uint32((fileSize + chunkSize - 1) / chunkSize)

	peersMu.Lock()
	defer peersMu.Unlock()

	var totalEncryptTime time.Duration
	for chunkID := uint32(0); chunkID < totalChunks; chunkID++ {
		chunk := make([]byte, chunkSize)
		n, err := file.Read(chunk)
		if err != nil && err != io.EOF {
			return err
		}
		chunk = chunk[:n]

		var dataType uint8
		switch filepath.Ext(filename) {
		case ".jpg", ".png":
			dataType = 1
		case ".mp4":
			dataType = 2
		case ".pdf":
			dataType = 3
		default:
			dataType = 4
		}

		header := MessageHeader{
			Type:        dataType,
			ChunkID:     chunkID,
			TotalChunks: totalChunks,
			MetadataLen: uint16(len(filename)),
			Metadata:    filename,
		}
		data := encodeHeader(header)
		data = append(data, chunk...)

		for _, peer := range peers {
			conn := peer.conn
			gcm := peer.gcm
			conn.SetWriteDeadline(time.Now().Add(msgTimeout))
			nonce := make([]byte, gcm.NonceSize())
			rand.Read(nonce)

			startEncrypt := time.Now()
			ciphertext := gcm.Seal(nonce, nonce, data, nil)
			encryptDuration := time.Since(startEncrypt)
			totalEncryptTime += encryptDuration

			encryptMs := float64(encryptDuration.Nanoseconds()) / 1e6
			fmt.Printf("%s[STATS]%s Chunk %d Encryption to %s: %.3f ms\n", Cyan, Reset, chunkID, peer.addr, encryptMs)

			err := binary.Write(conn, binary.BigEndian, uint32(len(ciphertext)))
			if err != nil {
				fmt.Printf("%s[ERROR]%s Failed to send chunk length to %s: %v\n", Red, Reset, peer.addr, err)
				continue
			}
			_, err = conn.Write(ciphertext)
			if err != nil {
				fmt.Printf("%s[ERROR]%s Failed to send chunk to %s: %v\n", Red, Reset, peer.addr, err)
				continue
			}
		}
	}
	totalEncryptMs := float64(totalEncryptTime.Nanoseconds()) / 1e6
	fmt.Printf("%s[STATS]%s Total Encryption Time for %s (%d bytes, %d chunks): %.3f ms\n",
		Cyan, Reset, filename, fileSize, totalChunks, totalEncryptMs)
	fmt.Printf("%s[INFO]%s Sent file: %s\n", Green, Reset, filename)
	return nil
}

func encodeHeader(header MessageHeader) []byte {
	data := []byte{header.Type}
	chunkID := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkID, header.ChunkID)
	data = append(data, chunkID...)
	totalChunks := make([]byte, 4)
	binary.BigEndian.PutUint32(totalChunks, header.TotalChunks)
	data = append(data, totalChunks...)
	metadataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(metadataLen, header.MetadataLen)
	data = append(data, metadataLen...)
	data = append(data, []byte(header.Metadata)...)
	return data
}
