package udp

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	udpBufferSize   = 65507 // Maximum UDP packet size
	chunkHeaderSize = 5     // 1 byte for message type + 4 bytes for sequence number
	maxChunkSize    = udpBufferSize - chunkHeaderSize
	authTimeout     = 5 * time.Second
	msgTimeout      = 10 * time.Second
)

// Message types
const (
	msgTypeKeyExchange = 0x02
	msgTypeData        = 0x03
	msgTypeFileStart   = 0x04
	msgTypeFileChunk   = 0x05
	msgTypeFileEnd     = 0x06
)

type FileChunk struct {
	Sequence uint32
	Data     []byte
}

type UDPPeer struct {
	conn         *net.UDPConn
	gcm          cipher.AEAD
	hybridKey    []byte
	addr         *net.UDPAddr
	localPort    string
	pqcAlgo      string
	mu           sync.Mutex
	isServer     bool
	fileBuffer   map[string][]FileChunk
	expectedSize map[string]int64
	chunkSize    map[string]int // Track chunk size for each file
}

type UDPMessage struct {
	Type    uint8
	Payload []byte
}

var (
	udpPeers   = make(map[string]*UDPPeer)
	udpPeersMu sync.Mutex
)

func NewUDPPeer(port, pqcAlgo string) (*UDPPeer, error) {
	addr, err := net.ResolveUDPAddr("udp", port)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	return &UDPPeer{
		conn:         conn,
		localPort:    port,
		pqcAlgo:      pqcAlgo,
		fileBuffer:   make(map[string][]FileChunk),
		expectedSize: make(map[string]int64),
		chunkSize:    make(map[string]int),
	}, nil
}

func (p *UDPPeer) Close() error {
	return p.conn.Close()
}

func (p *UDPPeer) ConnectTo(remoteAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return err
	}

	// Get PQC scheme
	scheme, err := getKEMScheme(p.pqcAlgo)
	if err != nil {
		return err
	}

	if scheme == nil {
		// If no PQC scheme is specified, just store the address
		p.addr = addr
		return nil
	}

	// Generate key pair
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Send public key
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return err
	}
	msg := append([]byte{msgTypeKeyExchange}, pkBytes...)
	if _, err := p.conn.WriteToUDP(msg, addr); err != nil {
		return err
	}

	// Receive ciphertext
	buffer := make([]byte, scheme.CiphertextSize()+1) // +1 for message type
	n, _, err := p.conn.ReadFromUDP(buffer)
	if err != nil {
		return err
	}

	// Verify message type
	if buffer[0] != msgTypeKeyExchange {
		return fmt.Errorf("unexpected message type")
	}

	// Get shared secret
	shared, err := scheme.Decapsulate(sk, buffer[1:n])
	if err != nil {
		return err
	}

	p.hybridKey = shared
	p.addr = addr
	return nil
}

func (p *UDPPeer) Listen() error {
	buffer := make([]byte, udpBufferSize)
	for {
		n, addr, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}

		// Handle incoming message
		msg := buffer[:n]
		if err := p.handleMessage(msg, addr); err != nil {
			// Handle error appropriately
			continue
		}
	}
}

func (p *UDPPeer) handleMessage(data []byte, addr *net.UDPAddr) error {
	if len(data) < 1 {
		return nil // Invalid message
	}

	msgType := data[0]
	payload := data[1:]

	fmt.Printf("Received message type: %d from %s\n", msgType, addr.String())

	switch msgType {
	case msgTypeKeyExchange:
		return p.handleKeyExchange(payload, addr)
	case msgTypeData:
		return p.handleData(payload, addr)
	case msgTypeFileStart:
		return p.handleFileStart(payload, addr)
	case msgTypeFileChunk:
		return p.handleFileChunk(payload, addr)
	case msgTypeFileEnd:
		return p.handleFileEnd(payload, addr)
	default:
		return fmt.Errorf("unknown message type: %d", msgType)
	}
}

func (p *UDPPeer) handleKeyExchange(payload []byte, addr *net.UDPAddr) error {
	// Get PQC scheme
	scheme, err := getKEMScheme(p.pqcAlgo)
	if err != nil {
		return err
	}

	// Server side
	if p.isServer {
		// Generate key pair
		pk, sk, err := scheme.GenerateKeyPair()
		if err != nil {
			return err
		}

		// Send public key
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return err
		}
		msg := append([]byte{0x02}, pkBytes...)
		if _, err := p.conn.WriteToUDP(msg, addr); err != nil {
			return err
		}

		// Receive ciphertext
		buffer := make([]byte, scheme.CiphertextSize()+1) // +1 for message type
		n, _, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}

		// Verify message type
		if buffer[0] != 0x02 {
			return fmt.Errorf("unexpected message type")
		}

		// Get shared secret
		shared, err := scheme.Decapsulate(sk, buffer[1:n])
		if err != nil {
			return err
		}

		p.hybridKey = shared
		p.addr = addr
		return nil
	}

	// Client side
	// Receive public key
	if len(payload) < 1 {
		return fmt.Errorf("invalid payload")
	}

	// Unmarshal public key
	pk, err := scheme.UnmarshalBinaryPublicKey(payload)
	if err != nil {
		return err
	}

	// Generate and send ciphertext
	ciphertext, shared, err := scheme.Encapsulate(pk)
	if err != nil {
		return err
	}

	msg := append([]byte{0x02}, ciphertext...)
	if _, err := p.conn.WriteToUDP(msg, addr); err != nil {
		return err
	}

	p.hybridKey = shared
	p.addr = addr
	return nil
}

func (p *UDPPeer) handleData(payload []byte, addr *net.UDPAddr) error {
	// 1. Decrypt the data using our hybrid key
	// payload contains encrypted data from sender
	decrypted, err := p.gcm.Open(nil, payload[:p.gcm.NonceSize()],
		payload[p.gcm.NonceSize():], nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	// 2. Process the decrypted data
	// This could be:
	// - Saving to a file
	// - Displaying the message
	// - Processing the data in some way
	fmt.Printf("Received data from %s: %s\n", addr.String(), string(decrypted))

	return nil
}

func (p *UDPPeer) SendFile(filePath string, remoteAddr string) error {
	if p.addr == nil {
		return fmt.Errorf("not connected to any peer")
	}

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Get the file name
	fileName := filepath.Base(filePath)
	fmt.Printf("Starting to send file: %s (%d bytes)\n", fileName, len(data))

	// Send file start message with size
	startMsg := append([]byte{msgTypeFileStart}, []byte(fmt.Sprintf("%s|%d", fileName, len(data)))...)
	if _, err := p.conn.WriteToUDP(startMsg, p.addr); err != nil {
		return err
	}

	// Split file into chunks and send
	totalChunks := (len(data) + maxChunkSize - 1) / maxChunkSize
	seq := uint32(0)

	for i := 0; i < len(data); i += maxChunkSize {
		end := i + maxChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Create chunk message with sequence number
		seqBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(seqBytes, seq)
		chunkMsg := append([]byte{msgTypeFileChunk}, seqBytes...)
		chunkMsg = append(chunkMsg, chunk...)

		// Send chunk with retry
		for retry := 0; retry < 3; retry++ {
			if _, err := p.conn.WriteToUDP(chunkMsg, p.addr); err != nil {
				if retry == 2 {
					return fmt.Errorf("failed to send chunk %d after 3 retries: %v", seq, err)
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}

		fmt.Printf("Sent chunk %d/%d (%d bytes)\n", seq+1, totalChunks, len(chunk))
		seq++
	}

	// Send file end message
	endMsg := append([]byte{msgTypeFileEnd}, []byte(fileName)...)
	if _, err := p.conn.WriteToUDP(endMsg, p.addr); err != nil {
		return err
	}

	fmt.Printf("File %s sent successfully\n", fileName)
	return nil
}

func (p *UDPPeer) handleFileStart(payload []byte, addr *net.UDPAddr) error {
	// Payload format: filename|size
	parts := strings.Split(string(payload), "|")
	if len(parts) != 2 {
		return fmt.Errorf("invalid file start message")
	}

	fileName := parts[0]
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid file size: %v", err)
	}

	p.fileBuffer[fileName] = []FileChunk{}
	p.expectedSize[fileName] = size
	p.chunkSize[fileName] = maxChunkSize
	fmt.Printf("Starting to receive file: %s (expected size: %d bytes)\n", fileName, size)
	return nil
}

func (p *UDPPeer) handleFileChunk(payload []byte, addr *net.UDPAddr) error {
	if len(payload) < 4 {
		return fmt.Errorf("invalid chunk size")
	}

	// First 4 bytes are sequence number
	seq := binary.BigEndian.Uint32(payload[:4])
	chunkData := payload[4:]

	// Find the file this chunk belongs to
	var currentFile string
	for file := range p.fileBuffer {
		currentFile = file
		break
	}
	if currentFile == "" {
		return fmt.Errorf("received chunk without file start")
	}

	// Add chunk to buffer
	p.fileBuffer[currentFile] = append(p.fileBuffer[currentFile], FileChunk{
		Sequence: seq,
		Data:     chunkData,
	})

	fmt.Printf("Received chunk %d (%d bytes)\n", seq, len(chunkData))
	return nil
}

func (p *UDPPeer) handleFileEnd(payload []byte, addr *net.UDPAddr) error {
	fileName := string(payload)
	chunks := p.fileBuffer[fileName]
	expectedSize := p.expectedSize[fileName]

	// Sort chunks by sequence number
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].Sequence < chunks[j].Sequence
	})

	// Pre-allocate buffer for the entire file
	data := make([]byte, expectedSize)
	offset := int64(0)

	// Copy chunks into the buffer
	for _, chunk := range chunks {
		copy(data[offset:], chunk.Data)
		offset += int64(len(chunk.Data))
	}

	// Verify size
	if offset != expectedSize {
		return fmt.Errorf("file size mismatch: expected %d, got %d", expectedSize, offset)
	}

	// Save the file
	if err := os.WriteFile(fileName, data, 0644); err != nil {
		return fmt.Errorf("failed to save file: %v", err)
	}

	fmt.Printf("File received and saved: %s (%d bytes)\n", fileName, offset)
	delete(p.fileBuffer, fileName)
	delete(p.expectedSize, fileName)
	delete(p.chunkSize, fileName)
	return nil
}

func getKEMScheme(pqcAlgo string) (kem.Scheme, error) {
	// Reuse the same KEM scheme selection as in the TCP implementation
	switch pqcAlgo {
	case "kyber":
		return kyber512.Scheme(), nil
	case "frodo":
		return frodo640shake.Scheme(), nil
	case "mlkem":
		return mlkem768.Scheme(), nil
	default:
		return nil, nil // Use ECDH only
	}
}
