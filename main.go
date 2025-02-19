package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Upstream represents an upstream DNS server.
type Upstream struct {
	Address  string // For UDP/TCP, host:port (e.g. "8.8.8.8:53"). For HTTPS, the full URL (e.g. "https://1.1.1.1/dns-query")
	IsIPv4   bool   // whether this upstream is IPv4
	Protocol string // "udp", "tcp", or "https"
}

// Upstream servers to query (order doesn’t matter since we query concurrently).
var upstreams = []Upstream{
	/*{Address: "8.8.8.8:53", IsIPv4: true, Protocol: "udp"},
	{Address: "8.8.4.4:53", IsIPv4: true, Protocol: "udp"},
	{Address: "[2001:4860:4860::8888]:53", IsIPv4: false, Protocol: "udp"},
	{Address: "[2001:4860:4860::8844]:53", IsIPv4: false, Protocol: "udp"},*/
	// DNS-over-HTTPS upstream (Cloudflare DoH endpoint)
	{Address: "https://1.1.1.1/dns-query", IsIPv4: true, Protocol: "https"},
}

// upstreamResponse carries the result of one upstream query.
type upstreamResponse struct {
	msg    *dns.Msg
	IsIPv4 bool
	Source string // the upstream server address that responded
	err    error
}

// cacheEntry holds a cached DNS reply with its expiration time.
type cacheEntry struct {
	msg         *dns.Msg
	expires     time.Time
	originalTTL uint32
	created     time.Time
}

// cache stores responses keyed by the query (question name + type).
var (
	cache      = make(map[string]cacheEntry)
	cacheMutex sync.RWMutex

	// fileLogger will log query details to a file.
	fileLogger *log.Logger
)

// Enforce a minimum TTL so zero/low TTLs from upstream won't disable caching.
const defaultMinTTL = 30

// cacheKey builds a key for caching based on the first question.
// We canonicalize by lowercasing and calling dns.Fqdn() so that
// "Example.com" vs. "example.com." become consistent keys.
func cacheKey(req *dns.Msg) string {
	if len(req.Question) > 0 {
		q := req.Question[0]
		name := strings.ToLower(dns.Fqdn(q.Name))
		return name + ":" + dns.TypeToString[q.Qtype]
	}
	return ""
}

// getCachedResponse returns a cached reply if available and not expired.
func getCachedResponse(key string) (*dns.Msg, bool) {
	cacheMutex.RLock()
	entry, found := cache[key]
	cacheMutex.RUnlock()

	if !found {
		return nil, false
	}

	now := time.Now()
	if now.After(entry.expires) {
		// Expired—remove from cache
		cacheMutex.Lock()
		delete(cache, key)
		cacheMutex.Unlock()
		return nil, false
	}

	// Calculate remaining TTL
	remainingSecs := uint32(entry.expires.Sub(now).Seconds())

	// Create a copy and update its TTL values
	response := entry.msg.Copy()
	for i := range response.Answer {
		response.Answer[i].Header().Ttl = remainingSecs
	}
	for i := range response.Ns {
		response.Ns[i].Header().Ttl = remainingSecs
	}
	for i := range response.Extra {
		response.Extra[i].Header().Ttl = remainingSecs
	}

	return response, true
}

// setCache stores the reply in the cache using the smallest TTL found in the message (Answer/Ns/Extra).
func setCache(key string, msg *dns.Msg) {
	var minTTL uint32 = 0xffffffff

	// Find the minimum TTL in the entire response
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	for _, rr := range msg.Extra {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	// If the response has no records, fallback to 60
	if minTTL == 0xffffffff {
		minTTL = 60
	} else if minTTL < defaultMinTTL {
		// Enforce a minimum TTL
		minTTL = defaultMinTTL
	}

	now := time.Now()
	expires := now.Add(time.Duration(minTTL) * time.Second)

	cacheMutex.Lock()
	cache[key] = cacheEntry{
		msg:         msg.Copy(),
		expires:     expires,
		originalTTL: minTTL,
		created:     now,
	}
	cacheMutex.Unlock()

	log.Printf("Caching response for key=%s with minTTL=%d", key, minTTL)
	fileLogger.Printf("Caching response for key=%s with minTTL=%d", key, minTTL)
}

// queryUpstreams sends the DNS query concurrently to all upstream servers and returns the reply
// from the fastest server—with a short extra wait if the first reply is IPv6 (to see if an IPv4 answer arrives).
func queryUpstreams(req *dns.Msg) (*dns.Msg, string, error) {
	respCh := make(chan upstreamResponse, len(upstreams))

	// Launch queries concurrently
	for _, ups := range upstreams {
		go func(u Upstream) {
			if u.Protocol == "https" {
				// DNS-over-HTTPS logic
				httpClient := &http.Client{Timeout: 5 * time.Second}
				packed, err := req.Pack()
				if err != nil {
					respCh <- upstreamResponse{msg: nil, IsIPv4: u.IsIPv4, Source: u.Address, err: err}
					return
				}
				url := u.Address + "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
				httpResp, err := httpClient.Get(url)
				if err != nil {
					respCh <- upstreamResponse{msg: nil, IsIPv4: u.IsIPv4, Source: u.Address, err: err}
					return
				}
				defer httpResp.Body.Close()
				if httpResp.StatusCode != http.StatusOK {
					respCh <- upstreamResponse{
						msg:    nil,
						IsIPv4: u.IsIPv4,
						Source: u.Address,
						err:    fmt.Errorf("non-OK status: %d", httpResp.StatusCode),
					}
					return
				}
				body, err := io.ReadAll(httpResp.Body)
				if err != nil {
					respCh <- upstreamResponse{msg: nil, IsIPv4: u.IsIPv4, Source: u.Address, err: err}
					return
				}
				var dohMsg dns.Msg
				if err = dohMsg.Unpack(body); err != nil {
					respCh <- upstreamResponse{msg: nil, IsIPv4: u.IsIPv4, Source: u.Address, err: err}
					return
				}
				respCh <- upstreamResponse{msg: &dohMsg, IsIPv4: u.IsIPv4, Source: u.Address, err: nil}
			} else {
				// UDP/TCP
				client := new(dns.Client)
				client.Net = u.Protocol
				r, _, err := client.Exchange(req, u.Address)
				respCh <- upstreamResponse{msg: r, IsIPv4: u.IsIPv4, Source: u.Address, err: err}
			}
		}(ups)
	}

	totalUpstreams := len(upstreams)
	responsesReceived := 0
	var candidate upstreamResponse
	foundCandidate := false

	// Wait for the first non-error response
	for responsesReceived < totalUpstreams {
		resp := <-respCh
		responsesReceived++
		if resp.err != nil || resp.msg == nil {
			continue
		}
		candidate = resp
		foundCandidate = true
		break
	}

	if !foundCandidate {
		return nil, "", errors.New("all upstream queries failed")
	}

	// If the first good reply is IPv4, return it immediately.
	if candidate.IsIPv4 {
		return candidate.msg, candidate.Source, nil
	}

	// If first good reply is IPv6, wait briefly for IPv4
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()

	for responsesReceived < totalUpstreams {
		select {
		case resp := <-respCh:
			responsesReceived++
			if resp.err != nil || resp.msg == nil {
				continue
			}
			if resp.IsIPv4 {
				// Found IPv4—prefer it
				candidate = resp
				return candidate.msg, candidate.Source, nil
			}
		case <-timer.C:
			// Timer expired; return the IPv6 answer
			return candidate.msg, candidate.Source, nil
		}
	}

	return candidate.msg, candidate.Source, nil
}

// resolveDNS handles caching, upstream querying, and logging.
func resolveDNS(remoteAddr string, req *dns.Msg) (*dns.Msg, string, error) {
	var domain string
	if len(req.Question) > 0 {
		domain = req.Question[0].Name
	}

	// Log the incoming query.
	log.Printf("Received query from %s for %s", remoteAddr, domain)
	fileLogger.Printf("Received query from %s for %s", remoteAddr, domain)

	key := cacheKey(req)
	if cachedMsg, found := getCachedResponse(key); found {
		cachedMsg.Id = req.Id
		log.Printf("Serving from cache for %s (client: %s)", domain, remoteAddr)
		fileLogger.Printf("Serving from cache for %s (client: %s)", domain, remoteAddr)
		return cachedMsg, "cache", nil
	}

	// Not in cache or expired; query upstream
	resp, fastest, err := queryUpstreams(req)
	if err != nil {
		log.Printf("Error resolving %s for %s: %v", domain, remoteAddr, err)
		fileLogger.Printf("Error resolving %s for %s: %v", domain, remoteAddr, err)
		return nil, "", err
	}
	resp.Id = req.Id

	log.Printf("Responding to query for %s from client %s via upstream %s", domain, remoteAddr, fastest)
	fileLogger.Printf("Responding to query for %s from client %s via upstream %s", domain, remoteAddr, fastest)

	// Cache the new response
	setCache(key, resp)

	return resp, fastest, nil
}

// handleDNSRequest is the handler for DNS queries (used by UDP/TCP servers).
func handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	remoteAddr := w.RemoteAddr().String()
	resp, _, err := resolveDNS(remoteAddr, req)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	_ = w.WriteMsg(resp)
}

// dohHandler implements a simple DNS-over-HTTPS (DoH) endpoint.
// It supports GET (with base64url-encoded "dns" parameter) and POST (raw DNS message).
func dohHandler(w http.ResponseWriter, r *http.Request) {
	var reqMsg dns.Msg
	var err error

	switch r.Method {
	case http.MethodGet:
		// Expect ?dns= (base64url-encoded)
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing 'dns' parameter", http.StatusBadRequest)
			return
		}
		data, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "failed to decode 'dns' parameter", http.StatusBadRequest)
			return
		}
		if err = reqMsg.Unpack(data); err != nil {
			http.Error(w, "failed to unpack DNS message", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		// POST body should be raw DNS message
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if err = reqMsg.Unpack(data); err != nil {
			http.Error(w, "failed to unpack DNS message", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remoteAddr := r.RemoteAddr
	resp, _, err := resolveDNS(remoteAddr, &reqMsg)
	if err != nil {
		http.Error(w, "DNS query failed", http.StatusInternalServerError)
		return
	}

	// Pack the DNS response.
	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.Write(packed)
	if err != nil {
		log.Printf("failed to write HTTP response: %v", err)
	}
}

func main() {
	// Open (or create) a log file to record queries.
	f, err := os.OpenFile("dns_queries.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	fileLogger = log.New(f, "", log.LstdFlags)

	// Set up the DNS handler (UDP and TCP).
	dns.HandleFunc(".", handleDNSRequest)

	// Start DNS on UDP
	udpServer := &dns.Server{
		Addr:    ":53",
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}
	go func() {
		log.Printf("Starting DNS server on UDP %s", udpServer.Addr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %s", err.Error())
		}
	}()

	// Start DNS on TCP
	tcpServer := &dns.Server{
		Addr:    ":53",
		Net:     "tcp",
		Handler: dns.DefaultServeMux,
	}
	go func() {
		log.Printf("Starting DNS server on TCP %s", tcpServer.Addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP server: %s", err.Error())
		}
	}()

	// Start HTTP (DoH) on :8080
	http.HandleFunc("/dns-query", dohHandler)
	go func() {
		httpAddr := ":8080"
		log.Printf("Starting HTTP server (DoH) on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, nil); err != nil {
			log.Fatalf("Failed to start HTTP server: %s", err.Error())
		}
	}()

	// Block forever.
	select {}
}
