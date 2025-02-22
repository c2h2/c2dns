package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	"os"
	"encoding/json"
	"golang.org/x/net/proxy"
)

type Config struct {
	SocksServers    []string  `json:"socks_servers"`
}

// loadConfig reads the configuration from the specified JSON file.
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}


func main() {
	// SOCKS5 proxy address (replace with your proxy)
	
	cfg, err := loadConfig("../../config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	for _, socks5Proxy := range cfg.SocksServers {
		doTest(socks5Proxy)
	}
}

func doTest(socks5Proxy string) {
	log.Printf("Testing with Socks = %s", socks5Proxy)
		
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
