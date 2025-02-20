package main

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
	"time"
)

var DNS_UPSTREAM = "8.8.8.8:53"

type DNSCache struct {
	entries map[string]cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	data      []byte
	timestamp time.Time
}

func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

func (cache *DNSCache) get(query string) ([]byte, bool) {
	return nil, false //testing

	entry, found := cache.entries[query]
	if !found {
		return nil, false
	}
	// Check if cache is still valid
	if time.Since(entry.timestamp) < cache.ttl {
		return entry.data, true
	}
	// Evict expired cache
	delete(cache.entries, query)
	return nil, false
}

func (cache *DNSCache) set(query string, data []byte) {
	cache.entries[query] = cacheEntry{
		data:      data,
		timestamp: time.Now(),
	}
}

func queryUpstream(query string) ([]byte, error) {
	c := &dns.Client{}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(query), dns.TypeA)
	r, _, err := c.Exchange(msg, DNS_UPSTREAM)
	if err != nil {
		return nil, err
	}

	// Build the response
	if len(r.Answer) > 0 {
		return r.Pack()
	}
	return nil, fmt.Errorf("no answer for query: %s", query)
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg, cache *DNSCache) {
	query := r.Question[0].Name

	// Check cache first
	cachedData, found := cache.get(query)
	if found {
		fmt.Println("\033[32mCache hit:", query, "\033[0m")
		w.Write(cachedData)
		return
	}

	// If not in cache, query upstream (1.1.1.1)
	upstreamData, err := queryUpstream(query)
	if err != nil {
		fmt.Println("\033[31mFailed to resolve:", query, "\033[0m")
		r.SetRcode(r, dns.RcodeNameError)
		resp, _ := r.Pack() // Ignoring the error here as it's not critical
		w.Write(resp)
		return
	}

	// Cache the result
	cache.set(query, upstreamData)
	fmt.Println("\033[32mSuccessfully resolved:", query, "\033[0m")

	// Ensure the transaction ID is preserved and append the result to the Answer section
	r.Answer = nil             // Clear previous answers
	r.Extra = nil              // Clear any extra records
	// r.Authority = nil          // No authority section needed for now

	// Create a new DNS message from the upstream response bytes
	msg := new(dns.Msg)
	if err := msg.Unpack(upstreamData); err != nil {
		fmt.Println("Error unpacking DNS response:", err)
		return
	}

	// Copy the answers from the unpacked message
	r.Answer = msg.Answer
	r.Extra = msg.Extra
	r.Ns = msg.Ns

	resp, err := r.Pack()
	if err != nil {
		fmt.Println("Error packing DNS response:", err)
		return
	}
	w.Write(resp)
}

func startDNSServer(cache *DNSCache) {
	handler := dns.NewServeMux()
	handler.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleRequest(w, r, cache)
	})

	server := &dns.Server{Addr: ":53", Net: "udp", Handler: handler}
	fmt.Println("Starting DNS proxy server on port 53...")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Failed to start server:", err)
		os.Exit(1)
	}
}

func main() {
	cache := NewDNSCache(5 * time.Minute) // Set TTL to 5 minutes

	// Start the DNS proxy server
	startDNSServer(cache)
}