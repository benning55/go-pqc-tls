package udp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	MaxPacketSize = 1400 // Standard MTU size minus UDP/IP headers
	WindowSize    = 5    // Number of packets that can be sent without acknowledgment
	Timeout       = 500 * time.Millisecond
)

type Packet struct {
	SeqNum uint32
	Data   []byte
}

type SimpleUDPPeer struct {
	conn         *net.UDPConn
	window       []Packet
	base         uint32
	nextSeqNum   uint32
	lastAck      uint32
	lastAckTime  time.Time
	timeoutTimer *time.Timer
	sharedKey    []byte
}

// AES encryption helper functions
func encryptData(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data)) // IV + data
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func decryptData(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	decrypted := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decrypted, ciphertext)

	return decrypted, nil
}

func NewSimpleUDPPeer(listenAddr string, sharedKey []byte) (*SimpleUDPPeer, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	return &SimpleUDPPeer{
		conn:         conn,
		window:       make([]Packet, WindowSize),
		base:         0,
		nextSeqNum:   0,
		lastAck:      0,
		timeoutTimer: time.NewTimer(Timeout),
		sharedKey:    sharedKey,
	}, nil
}

func (p *SimpleUDPPeer) Close() error {
	if p.timeoutTimer != nil {
		p.timeoutTimer.Stop()
	}
	return p.conn.Close()
}

func (p *SimpleUDPPeer) SendFile(filePath string, remoteAddr string) error {
	// Read the file
	file, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	fmt.Printf("Sending file %s, size: %d bytes\n", filePath, len(file))

	filename := []byte(filepath.Base(filePath))
	fmt.Printf("Sending filename: %s (bytes: %v)\n", filename, filename)

	// Resolve remote address
	addr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve remote address %s: %v", remoteAddr, err)
	}

	// Encrypt the filename
	encryptedFilename, err := encryptData(p.sharedKey, filename)
	if err != nil {
		return fmt.Errorf("failed to encrypt filename: %v", err)
	}

	// Send filename packet
	filenamePacket := Packet{
		SeqNum: p.nextSeqNum,
		Data:   encryptedFilename,
	}
	p.window[p.nextSeqNum%WindowSize] = filenamePacket
	if err := p.sendPacket(filenamePacket, addr); err != nil {
		return err
	}
	if err := p.waitForAck(addr); err != nil {
		return err
	}
	p.nextSeqNum++

	// Send file in chunks
	for i := 0; i < len(file); i += MaxPacketSize {
		end := i + MaxPacketSize
		if end > len(file) {
			end = len(file)
		}

		chunk := file[i:end]
		fmt.Printf("Sending chunk %d, size: %d bytes, first 10 bytes: %x\n", p.nextSeqNum, len(chunk), chunk[:min(10, len(chunk))])

		// Encrypt the chunk
		encryptedData, err := encryptData(p.sharedKey, chunk)
		if err != nil {
			return fmt.Errorf("failed to encrypt chunk %d: %v", p.nextSeqNum, err)
		}

		// Create packet
		packet := Packet{
			SeqNum: p.nextSeqNum,
			Data:   encryptedData,
		}

		// Add packet to window
		p.window[p.nextSeqNum%WindowSize] = packet

		// Send packet
		if err := p.sendPacket(packet, addr); err != nil {
			return err
		}

		// Wait for acknowledgment
		if err := p.waitForAck(addr); err != nil {
			return err
		}

		p.nextSeqNum++
	}

	// Send end of file signal
	endPacket := Packet{
		SeqNum: p.nextSeqNum,
		Data:   []byte{},
	}
	if err := p.sendPacket(endPacket, addr); err != nil {
		return err
	}

	fmt.Println("File sent successfully")
	return nil
}

func (p *SimpleUDPPeer) sendPacket(packet Packet, addr *net.UDPAddr) error {
	// Create buffer with sequence number
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf[:4], packet.SeqNum)

	// Use packet.Data directly (already encrypted in SendFile)
	data := packet.Data

	// Append data to buffer
	buf = append(buf, data...)

	_, err := p.conn.WriteToUDP(buf, addr)
	if err != nil {
		return fmt.Errorf("failed to send packet seq %d: %v", packet.SeqNum, err)
	}

	return nil
}

func (p *SimpleUDPPeer) waitForAck(addr *net.UDPAddr) error {
	p.timeoutTimer.Reset(Timeout)

	for {
		select {
		case <-p.timeoutTimer.C:
			// Timeout occurred, resend all packets in window
			for i := p.base; i < p.nextSeqNum; i++ {
				if err := p.sendPacket(p.window[i%WindowSize], addr); err != nil {
					return err
				}
			}
			p.timeoutTimer.Reset(Timeout)

		default:
			// Read acknowledgment
			buf := make([]byte, 4)
			n, _, err := p.conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			if n == 4 {
				ack := binary.BigEndian.Uint32(buf)
				if ack >= p.base {
					p.base = ack + 1
					p.lastAck = ack
					p.lastAckTime = time.Now()
					return nil
				}
			}
		}
	}
}

func (p *SimpleUDPPeer) ReceiveFile(outputDir string) error {
	var file *os.File
	expectedSeqNum := uint32(0)
	buffer := make([]byte, MaxPacketSize+4+aes.BlockSize) // +4 for seqNum, +aes.BlockSize for IV
	totalBytesWritten := int64(0)

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %v", outputDir, err)
	}
	if _, err := os.Stat(outputDir); err != nil {
		return fmt.Errorf("cannot access output directory %s: %v", outputDir, err)
	}
	fmt.Printf("Output directory: %s\n", outputDir)

	for {
		n, addr, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			return fmt.Errorf("failed to read packet: %v", err)
		}

		if n < 4 {
			continue // Invalid packet
		}

		seqNum := binary.BigEndian.Uint32(buffer[:4])
		data := buffer[4:n]

		// Debug: Log received packet
		fmt.Printf("Seq %d: Received %d bytes\n", seqNum, n)

		// Handle EOF packet (empty data)
		if len(data) == 0 {
			fmt.Printf("End of file received for seq %d, total bytes written: %d\n", seqNum, totalBytesWritten)
			// Send acknowledgment
			ackBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(ackBuf, seqNum)
			if _, err := p.conn.WriteToUDP(ackBuf, addr); err != nil {
				return fmt.Errorf("failed to send ack for seq %d: %v", seqNum, err)
			}
			break
		}

		// Decrypt data if we have a shared key
		var decryptedData []byte
		if p.sharedKey != nil {
			fmt.Printf("Seq %d: Attempting decryption of %d bytes\n", seqNum, len(data))
			decryptedData, err = decryptData(p.sharedKey, data)
			if err != nil {
				return fmt.Errorf("failed to decrypt data for seq %d: %v", seqNum, err)
			}
		} else {
			return fmt.Errorf("no shared key available for seq %d", seqNum)
		}

		// Debug: Log decrypted data
		fmt.Printf("Seq %d: Decrypted size: %d bytes, first 10 bytes: %x\n",
			seqNum, len(decryptedData), decryptedData[:min(10, len(decryptedData))])

		// Send acknowledgment
		ackBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(ackBuf, seqNum)
		if _, err := p.conn.WriteToUDP(ackBuf, addr); err != nil {
			return fmt.Errorf("failed to send ack for seq %d: %v", seqNum, err)
		}

		if seqNum == expectedSeqNum {
			if file == nil {
				// First packet contains the filename
				filename := string(bytes.TrimRight(decryptedData, "\x00"))
				filename = filepath.Base(filename)
				filename = strings.TrimSpace(filename)
				if filename == "" {
					return fmt.Errorf("invalid filename: empty after trimming")
				}

				fmt.Printf("Raw filename bytes: %v\n", decryptedData)
				fmt.Printf("Decrypted filename: %s\n", filename)
				fmt.Printf("Filename hex: %x\n", filename)

				fullPath := filepath.Join(outputDir, filename)
				absPath, err := filepath.Abs(fullPath)
				if err != nil {
					return fmt.Errorf("failed to get absolute path for %s: %v", fullPath, err)
				}
				fmt.Printf("Creating file at: %s (absolute: %s)\n", fullPath, absPath)

				if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
					return fmt.Errorf("cannot create file %s: path is a directory", fullPath)
				}

				file, err = os.Create(fullPath)
				if err != nil {
					return fmt.Errorf("failed to create file %s: %v", fullPath, err)
				}
				defer file.Close()
			} else {
				// Write data chunks
				n, err := file.Write(decryptedData)
				if err != nil {
					return fmt.Errorf("failed to write chunk for seq %d: %v", seqNum, err)
				}
				totalBytesWritten += int64(n)
				fmt.Printf("Wrote %d bytes for seq %d, total: %d\n", n, seqNum, totalBytesWritten)
			}
			expectedSeqNum++
		} else {
			fmt.Printf("Out-of-order packet: got seq %d, expected %d\n", seqNum, expectedSeqNum)
		}
	}

	return nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
