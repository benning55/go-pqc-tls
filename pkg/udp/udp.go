package udp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	MTUSize      = 1400 // Standard MTU size minus UDP/IP headers
	WindowSize   = 5    // Number of packets that can be sent without acknowledgment
	Timeout      = 500 * time.Millisecond
	SmallFileMax = 1024 * 1024 // 1MB
)

type Packet struct {
	SeqNum  uint32
	Data    []byte
	Metrics *ChunkMetric
}

type TransferMetrics struct {
	TransferType       string    // "sender" or "receiver"
	Timestamp          time.Time // Time of transfer completion
	Filename           string
	FileSize           int
	TotalChunks        int
	ChunkSize          int
	Chunks             []ChunkMetric
	TotalTimeMs        float64
	AvgChunkTimeMs     float64
	TotalEncryptTimeMs float64
	AvgEncryptTimeMs   float64
	TotalDecryptTimeMs float64
	AvgDecryptTimeMs   float64
}

type ChunkMetric struct {
	ChunkNum      int
	ChunkSize     int
	EncryptTimeMs float64
	DecryptTimeMs float64
	TotalTimeMs   float64
	SpeedMBps     float64
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
	logFile      *os.File
	logMutex     sync.Mutex // Mutex for thread-safe logging
}

// AES encryption helper functions
func encryptData(key []byte, data []byte) ([]byte, error) {
	start := time.Now()
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

	duration := time.Since(start).Seconds() * 1000
	debugLog(fmt.Sprintf("Encryption of %d bytes took %.6f ms", len(data), duration))
	return ciphertext, nil
}

func decryptData(key []byte, ciphertext []byte) ([]byte, error) {
	start := time.Now()
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

	duration := time.Since(start).Seconds() * 1000
	debugLog(fmt.Sprintf("Decryption of %d bytes took %.6f ms", len(ciphertext), duration))
	return decrypted, nil
}

func debugLog(msg string) {
	f, err := os.OpenFile("debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open debug.log: %v\n", err)
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	if _, err := f.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, msg)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write to debug.log: %v\n", err)
	}
}

func NewSimpleUDPPeer(listenAddr string, sharedKey []byte, logFile *os.File) (*SimpleUDPPeer, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		debugLog(fmt.Sprintf("Failed to resolve address %s: %v", listenAddr, err))
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		debugLog(fmt.Sprintf("Failed to listen on UDP %s: %v", listenAddr, err))
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	// Initialize transfers.json if no log file was provided
	if logFile == nil {
		var err error
		logFile, err = os.OpenFile("transfers.json", os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			debugLog(fmt.Sprintf("Failed to open transfers.json: %v", err))
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}

		// Initialize with empty JSON array if file is empty
		info, err := logFile.Stat()
		if err != nil {
			debugLog(fmt.Sprintf("Failed to stat transfers.json: %v", err))
			logFile.Close()
			return nil, fmt.Errorf("failed to stat log file: %v", err)
		}
		if info.Size() == 0 {
			if _, err := logFile.WriteString("[]\n"); err != nil {
				debugLog(fmt.Sprintf("Failed to initialize transfers.json: %v", err))
				logFile.Close()
				return nil, fmt.Errorf("failed to initialize log file: %v", err)
			}
		}
	}

	return &SimpleUDPPeer{
		conn:         conn,
		window:       make([]Packet, WindowSize),
		base:         0,
		nextSeqNum:   0,
		lastAck:      0,
		timeoutTimer: time.NewTimer(Timeout),
		sharedKey:    sharedKey,
		logFile:      logFile,
	}, nil
}

func (p *SimpleUDPPeer) Close() error {
	if p.timeoutTimer != nil {
		p.timeoutTimer.Stop()
	}
	if p.logFile != nil {
		return p.logFile.Close()
	}
	return p.conn.Close()
}

func (p *SimpleUDPPeer) log(metrics TransferMetrics) {
	if p.logFile == nil {
		debugLog("Log file is nil, cannot log metrics")
		return
	}

	debugLog(fmt.Sprintf("Logging metrics for %s transfer of %s", metrics.TransferType, metrics.Filename))

	// Lock for thread-safe file access
	p.logMutex.Lock()
	defer p.logMutex.Unlock()

	// Determine which log file to use based on transfer type
	logFileName := "encrypt.json"
	if metrics.TransferType == "receiver" {
		logFileName = "decrypt.json"
	}

	// Read existing JSON array
	data, err := os.ReadFile(logFileName)
	if err != nil && !os.IsNotExist(err) {
		debugLog(fmt.Sprintf("Failed to read %s: %v", logFileName, err))
		fmt.Fprintf(os.Stderr, "Failed to read log file: %v\n", err)
		return
	}

	var transfers []map[string]interface{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &transfers); err != nil {
			debugLog(fmt.Sprintf("Failed to unmarshal %s: %v", logFileName, err))
			fmt.Fprintf(os.Stderr, "Failed to unmarshal log data: %v\n", err)
			return
		}
	}

	// Format the metrics data
	formattedMetrics := map[string]interface{}{
		"data_type":       "Image",
		"filename":        metrics.Filename,
		"file_size_bytes": metrics.FileSize,
		"file_size_human": formatFileSize(metrics.FileSize),
		"total_chunks":    metrics.TotalChunks,
		"chunk_size":      formatChunkSizes(metrics.Chunks),
		"pqc_algorithm":   "Kyber",
	}

	// Add timing metrics based on transfer type
	if metrics.TransferType == "sender" {
		formattedMetrics["time_per_chunk"] = formatTimeRange(metrics.Chunks, "EncryptTimeMs")
		formattedMetrics["avg_time_per_chunk"] = fmt.Sprintf("%.6f ms", metrics.AvgEncryptTimeMs)
		formattedMetrics["total_time"] = fmt.Sprintf("%.6f ms", metrics.TotalEncryptTimeMs)
	} else {
		formattedMetrics["time_per_chunk"] = formatTimeRange(metrics.Chunks, "DecryptTimeMs")
		formattedMetrics["avg_time_per_chunk"] = fmt.Sprintf("%.6f ms", metrics.AvgDecryptTimeMs)
		formattedMetrics["total_time"] = fmt.Sprintf("%.6f ms", metrics.TotalDecryptTimeMs)
	}

	// Append new metrics
	transfers = append(transfers, formattedMetrics)

	// Marshal updated array
	jsonData, err := json.MarshalIndent(transfers, "", "  ")
	if err != nil {
		debugLog(fmt.Sprintf("Failed to marshal log data: %v", err))
		fmt.Fprintf(os.Stderr, "Failed to marshal log data: %v\n", err)
		return
	}

	// Write back to file
	if err := os.WriteFile(logFileName, jsonData, 0644); err != nil {
		debugLog(fmt.Sprintf("Failed to write %s: %v", logFileName, err))
		fmt.Fprintf(os.Stderr, "Failed to write log file: %v\n", err)
		return
	}

	// Print to console
	fmt.Println(string(jsonData))
	debugLog(fmt.Sprintf("Successfully wrote metrics to %s", logFileName))
}

// Helper function to format file size in human-readable format
func formatFileSize(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Helper function to format chunk sizes
func formatChunkSizes(chunks []ChunkMetric) string {
	if len(chunks) == 0 {
		return ""
	}

	// Count unique chunk sizes
	sizeCount := make(map[int]int)
	for _, chunk := range chunks {
		sizeCount[chunk.ChunkSize]++
	}

	// Format the result
	var parts []string
	for size, count := range sizeCount {
		parts = append(parts, fmt.Sprintf("%d (%d chunks)", size, count))
	}
	return strings.Join(parts, ", ")
}

// Helper function to format time range
func formatTimeRange(chunks []ChunkMetric, field string) string {
	if len(chunks) == 0 {
		return ""
	}

	var min, max float64
	switch field {
	case "EncryptTimeMs":
		min, max = chunks[0].EncryptTimeMs, chunks[0].EncryptTimeMs
		for _, chunk := range chunks {
			if chunk.EncryptTimeMs < min {
				min = chunk.EncryptTimeMs
			}
			if chunk.EncryptTimeMs > max {
				max = chunk.EncryptTimeMs
			}
		}
	case "DecryptTimeMs":
		min, max = chunks[0].DecryptTimeMs, chunks[0].DecryptTimeMs
		for _, chunk := range chunks {
			if chunk.DecryptTimeMs < min {
				min = chunk.DecryptTimeMs
			}
			if chunk.DecryptTimeMs > max {
				max = chunk.DecryptTimeMs
			}
		}
	}

	return fmt.Sprintf("%.6f–%.6f ms (%d chunks)", min, max, len(chunks))
}

// Helper function to determine chunk size based on file size
func getChunkSize(fileSize int) int {
	// Always use MTU size for UDP to avoid packet fragmentation
	return MTUSize
}

func (p *SimpleUDPPeer) SendFile(filePath string, remoteAddr string) error {
	file, err := os.ReadFile(filePath)
	if err != nil {
		debugLog(fmt.Sprintf("Failed to read file %s: %v", filePath, err))
		return fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	fileSize := len(file)
	filename := filepath.Base(filePath)

	// Determine chunk size based on file size
	chunkSize := getChunkSize(fileSize)
	totalChunks := (fileSize + chunkSize - 1) / chunkSize

	// Initialize metrics
	metrics := TransferMetrics{
		TransferType: "sender",
		Timestamp:    time.Now(),
		Filename:     filename,
		FileSize:     fileSize,
		TotalChunks:  totalChunks,
		ChunkSize:    chunkSize,
	}

	// Resolve remote address
	addr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		debugLog(fmt.Sprintf("Failed to resolve remote address %s: %v", remoteAddr, err))
		return fmt.Errorf("failed to resolve remote address %s: %v", remoteAddr, err)
	}

	// Send filename
	encryptedFilename, err := encryptData(p.sharedKey, []byte(filename))
	if err != nil {
		debugLog(fmt.Sprintf("Failed to encrypt filename: %v", err))
		return fmt.Errorf("failed to encrypt filename: %v", err)
	}
	filenamePacket := Packet{SeqNum: p.nextSeqNum, Data: encryptedFilename}
	p.window[p.nextSeqNum%WindowSize] = filenamePacket
	if err := p.sendPacket(filenamePacket, addr); err != nil {
		debugLog(fmt.Sprintf("Failed to send filename packet: %v", err))
		return err
	}
	if err := p.waitForAck(addr); err != nil {
		debugLog(fmt.Sprintf("Failed to wait for filename ack: %v", err))
		return err
	}
	p.nextSeqNum++

	// Send file in chunks
	for i := 0; i < len(file); i += chunkSize {
		end := i + chunkSize
		if end > len(file) {
			end = len(file)
		}
		chunk := file[i:end]
		chunkSize := len(chunk)
		chunkNum := i/chunkSize + 1

		// Encrypt chunk
		encryptStart := time.Now()
		encryptedData, err := encryptData(p.sharedKey, chunk)
		if err != nil {
			debugLog(fmt.Sprintf("Failed to encrypt chunk %d: %v", p.nextSeqNum, err))
			return fmt.Errorf("failed to encrypt chunk %d: %v", p.nextSeqNum, err)
		}
		encryptTime := time.Since(encryptStart).Seconds() * 1000
		debugLog(fmt.Sprintf("Encryption of chunk %d (%d bytes) took %.6f ms", chunkNum, chunkSize, encryptTime))

		// Send packet
		packet := Packet{SeqNum: p.nextSeqNum, Data: encryptedData}
		p.window[p.nextSeqNum%WindowSize] = packet
		if err := p.sendPacket(packet, addr); err != nil {
			debugLog(fmt.Sprintf("Failed to send chunk %d: %v", p.nextSeqNum, err))
			return err
		}
		if err := p.waitForAck(addr); err != nil {
			debugLog(fmt.Sprintf("Failed to wait for chunk %d ack: %v", p.nextSeqNum, err))
			return err
		}

		// Collect chunk metrics
		metrics.Chunks = append(metrics.Chunks, ChunkMetric{
			ChunkNum:      chunkNum,
			ChunkSize:     chunkSize,
			EncryptTimeMs: encryptTime,
			DecryptTimeMs: 0,           // Will be logged separately by receiver
			TotalTimeMs:   encryptTime, // Only include encryption time
			SpeedMBps:     float64(chunkSize) / 1024 / 1024 / (encryptTime / 1000),
		})

		p.nextSeqNum++
	}

	// Send EOF
	endPacket := Packet{SeqNum: p.nextSeqNum, Data: []byte{}}
	if err := p.sendPacket(endPacket, addr); err != nil {
		debugLog(fmt.Sprintf("Failed to send EOF packet: %v", err))
		return err
	}

	// Calculate and store summary metrics
	for _, chunk := range metrics.Chunks {
		metrics.TotalTimeMs += chunk.TotalTimeMs
		metrics.TotalEncryptTimeMs += chunk.EncryptTimeMs
	}
	if len(metrics.Chunks) > 0 {
		metrics.AvgChunkTimeMs = metrics.TotalTimeMs / float64(len(metrics.Chunks))
		metrics.AvgEncryptTimeMs = metrics.TotalEncryptTimeMs / float64(len(metrics.Chunks))
	}

	// Log metrics
	metrics.Timestamp = time.Now() // Update timestamp to completion time
	debugLog("Calling log method for sender")
	p.log(metrics)

	return nil
}

func (p *SimpleUDPPeer) sendPacket(packet Packet, addr *net.UDPAddr) error {
	// Create buffer with sequence number
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf[:4], packet.SeqNum)

	// Use packet.Data directly (already encrypted)
	data := packet.Data

	// Append data to buffer
	buf = append(buf, data...)

	_, err := p.conn.WriteToUDP(buf, addr)
	if err != nil {
		debugLog(fmt.Sprintf("Failed to send packet seq %d: %v", packet.SeqNum, err))
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
					debugLog(fmt.Sprintf("Failed to resend packet %d: %v", i, err))
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
	buffer := make([]byte, SmallFileMax+4+aes.BlockSize) // Use max possible chunk size
	totalBytesWritten := int64(0)
	metrics := TransferMetrics{
		TransferType: "receiver",
		Timestamp:    time.Now(),
		ChunkSize:    MTUSize, // Initial chunk size, will be updated with first packet
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		debugLog(fmt.Sprintf("Failed to create output directory %s: %v", outputDir, err))
		return fmt.Errorf("failed to create output directory %s: %v", outputDir, err)
	}

	for {
		n, addr, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			debugLog(fmt.Sprintf("Failed to read packet: %v", err))
			return fmt.Errorf("failed to read packet: %v", err)
		}
		if n < 4 {
			continue
		}

		seqNum := binary.BigEndian.Uint32(buffer[:4])
		data := buffer[4:n]

		if len(data) == 0 { // EOF
			ackBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(ackBuf, seqNum)
			p.conn.WriteToUDP(ackBuf, addr)
			break
		}

		// Decrypt data
		decryptStart := time.Now()
		decryptedData, err := decryptData(p.sharedKey, data)
		if err != nil {
			debugLog(fmt.Sprintf("Failed to decrypt data for seq %d: %v", seqNum, err))
			return fmt.Errorf("failed to decrypt data for seq %d: %v", seqNum, err)
		}
		decryptTime := time.Since(decryptStart).Seconds() * 1000
		debugLog(fmt.Sprintf("Decryption of chunk %d (%d bytes) took %.6f ms", seqNum, len(decryptedData), decryptTime))

		// Send acknowledgment
		ackBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(ackBuf, seqNum)
		p.conn.WriteToUDP(ackBuf, addr)

		if seqNum == expectedSeqNum {
			if file == nil {
				// Handle filename
				filename := strings.TrimSpace(string(bytes.TrimRight(decryptedData, "\x00")))
				metrics.Filename = filename
				fullPath := filepath.Join(outputDir, filepath.Base(filename))
				file, err = os.Create(fullPath)
				if err != nil {
					debugLog(fmt.Sprintf("Failed to create file %s: %v", fullPath, err))
					return fmt.Errorf("failed to create file %s: %v", fullPath, err)
				}
				defer file.Close()
			} else {
				// Write chunk
				n, err := file.Write(decryptedData)
				if err != nil {
					debugLog(fmt.Sprintf("Failed to write chunk for seq %d: %v", seqNum, err))
					return fmt.Errorf("failed to write chunk for seq %d: %v", seqNum, err)
				}
				totalBytesWritten += int64(n)
				metrics.Chunks = append(metrics.Chunks, ChunkMetric{
					ChunkNum:      len(metrics.Chunks) + 1,
					ChunkSize:     n,
					EncryptTimeMs: 0, // Will be logged separately by sender
					DecryptTimeMs: decryptTime,
					TotalTimeMs:   decryptTime, // Only include decryption time
				})
			}
			expectedSeqNum++
		}
	}

	// Calculate decryption stats
	for _, chunk := range metrics.Chunks {
		metrics.TotalDecryptTimeMs += chunk.DecryptTimeMs
	}
	if len(metrics.Chunks) > 0 {
		metrics.AvgDecryptTimeMs = metrics.TotalDecryptTimeMs / float64(len(metrics.Chunks))
	}
	metrics.FileSize = int(totalBytesWritten)
	metrics.TotalChunks = len(metrics.Chunks)

	// Log metrics
	metrics.Timestamp = time.Now() // Update timestamp to completion time
	debugLog("Calling log method for receiver")
	p.log(metrics)

	return nil
}

// Optional: Save metrics to SQLite database (requires github.com/mattn/go-sqlite3)
/*
import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

func (p *SimpleUDPPeer) saveMetricsToDB(metrics TransferMetrics) error {
	db, err := sql.Open("sqlite3", "./transfer_metrics.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// Create tables if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS transfers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			transfer_type TEXT,
			timestamp TEXT,
			filename TEXT,
			file_size INTEGER,
			total_chunks INTEGER,
			chunk_size INTEGER,
			total_time_ms REAL,
			avg_chunk_time_ms REAL,
			total_encrypt_time_ms REAL,
			avg_encrypt_time_ms REAL,
			total_decrypt_time_ms REAL,
			avg_decrypt_time_ms REAL
		);
		CREATE TABLE IF NOT EXISTS chunks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			transfer_id INTEGER,
			chunk_num INTEGER,
			chunk_size INTEGER,
			encrypt_time_ms REAL,
			total_time_ms REAL,
			speed_mbps REAL,
			decrypt_time_ms REAL,
			FOREIGN KEY(transfer_id) REFERENCES transfers(id)
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create tables: %v", err)
	}

	// Insert transfer record
	result, err := db.Exec(`
		INSERT INTO transfers (transfer_type, timestamp, filename, file_size, total_chunks, chunk_size, total_time_ms, avg_chunk_time_ms,
							  total_encrypt_time_ms, avg_encrypt_time_ms, total_decrypt_time_ms, avg_decrypt_time_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		metrics.TransferType, metrics.Timestamp.Format(time.RFC3339), metrics.Filename, metrics.FileSize, metrics.TotalChunks, metrics.ChunkSize,
		metrics.TotalTimeMs, metrics.AvgChunkTimeMs, metrics.TotalEncryptTimeMs, metrics.AvgEncryptTimeMs,
		metrics.TotalDecryptTimeMs, metrics.AvgDecryptTimeMs)
	if err != nil {
		return fmt.Errorf("failed to insert transfer: %v", err)
	}

	transferID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get transfer ID: %v", err)
	}

	// Insert chunk records
	for _, chunk := range metrics.Chunks {
		_, err = db.Exec(`
			INSERT INTO chunks (transfer_id, chunk_num, chunk_size, encrypt_time_ms, total_time_ms, speed_mbps, decrypt_time_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			transferID, chunk.ChunkNum, chunk.ChunkSize, chunk.EncryptTimeMs, chunk.TotalTimeMs, chunk.SpeedMBps, chunk.DecryptTimeMs)
		if err != nil {
			return fmt.Errorf("failed to insert chunk: %v", err)
		}
	}

	return nil
}
*/

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
