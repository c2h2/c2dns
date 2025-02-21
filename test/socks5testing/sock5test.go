package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	// SOCKS5 proxy address (replace with your proxy)
	socks5Proxy := "localhost:1080"

	// Target HTTPS URL
	url := "https://ifconfig.me"

	// Create a SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp", socks5Proxy, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Create a custom HTTP transport using the SOCKS5 dialer
	transport := &http.Transport{
		Dial:                dialer.Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Set the User-Agent to mimic curl
	req.Header.Set("User-Agent", "curl/8.7.1")

	// Make the HTTPS request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to make HTTPS request: %v", err)
	}
	defer resp.Body.Close()

	// Read and print the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body: %s\n", string(body))
}