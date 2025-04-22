package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/benning55/go-pqc-tls/pkg/udp"
)

func main() {
	listenPort := flag.String("listen", ":4433", "Port to listen on")
	connectAddrs := flag.String("connect", "", "Comma-separated addresses to connect to")
	pqcAlgo := flag.String("pqc", "", "Post-quantum key exchange algorithm (kyber, frodo, mlkem; empty for ECDH only)")
	sendFile := flag.String("send", "", "File to send")
	flag.Parse()

	// Create UDP peer
	peer, err := udp.NewUDPPeer(*listenPort, *pqcAlgo)
	if err != nil {
		fmt.Printf("Failed to create UDP peer: %v\n", err)
		os.Exit(1)
	}
	defer peer.Close()

	// Start listening in a separate goroutine
	go func() {
		if err := peer.Listen(); err != nil {
			fmt.Printf("Error in UDP listener: %v\n", err)
			os.Exit(1)
		}
	}()

	// Connect to remote peers if specified
	connectList := strings.Split(*connectAddrs, ",")
	var wg sync.WaitGroup
	for _, addr := range connectList {
		if addr == "" {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			if err := peer.ConnectTo(addr); err != nil {
				fmt.Printf("Failed to connect to %s: %v\n", addr, err)
			}
		}(addr)
	}
	wg.Wait()

	// Send file if specified
	if *sendFile != "" {
		if *connectAddrs == "" {
			fmt.Println("Error: Must specify remote address with -connect to send file")
			os.Exit(1)
		}
		if err := peer.SendFile(*sendFile, connectList[0]); err != nil {
			fmt.Printf("Failed to send file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File %s sent successfully\n", *sendFile)
		os.Exit(0)
	}

	// Keep the program running
	select {}
}
