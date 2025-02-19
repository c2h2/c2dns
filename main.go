package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var EXPIRE_MULTIPLIER int

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

// globalReqCount is a counter for all requests.
var globalReqCount uint64

// denyAAAA is set from the CLI flag; when true, AAAA answers will be removed if an A record exists.
var denyAAAA bool

// Enforce a minimum TTL so zero/low TTLs from upstream won't disable caching.
const defaultMinTTL = 30

// cacheKey builds a key for caching based on the first question.
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

// setCache stores the reply in the cache using the smallest TTL found in the message.
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
	expires := now.Add(time.Duration(minTTL) * time.Second * time.Duration(EXPIRE_MULTIPLIER))

	cacheMutex.Lock()
	cache[key] = cacheEntry{
		msg:         msg.Copy(),
		expires:     expires,
		originalTTL: minTTL,
		created:     now,
	}
	cacheMutex.Unlock()

	// Uncomment for debugging:
	// log.Printf("Caching response for key=%s with minTTL=%d", key, minTTL)
	// fileLogger.Printf("Caching response for key=%s with minTTL=%d", key, minTTL)
}

// queryUpstreams sends the DNS query concurrently to all upstream servers and returns the reply
// from the fastest server—with a short extra wait if the first reply is IPv6.
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
// It now accepts additional parameters for protocol, a global request ID, and the start time.
func resolveDNS(remoteAddr, protocol string, req *dns.Msg, reqID uint64, start time.Time) (*dns.Msg, string, error) {
	domain := ""
	if len(req.Question) > 0 {
		domain = req.Question[0].Name
	}

	// Start building a single log line.
	logLine := fmt.Sprintf("reqID=%d, remote=%s, domain=%s", reqID, remoteAddr, domain)

	key := cacheKey(req)
	if cachedMsg, found := getCachedResponse(key); found {
		// If served from cache
		cachedMsg.Id = req.Id
		logLine += ", served=cache"
		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		logLine += fmt.Sprintf(", proto=%s, time=%.3fms", protocol, ms)

		// Print once, in one line
		log.Println(logLine)
		fileLogger.Println(logLine)
		return cachedMsg, "cache", nil
	}

	// Otherwise, query upstream
	resp, fastest, err := queryUpstreams(req)
	if err != nil {
		logLine += fmt.Sprintf(", error=%v", err)
		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		logLine += fmt.Sprintf(", proto=%s, time=%.3fms", protocol, ms)
		log.Println(logLine)
		fileLogger.Println(logLine)
		return nil, "", err
	}

	// Successful upstream response
	resp.Id = req.Id
	setCache(key, resp)
	logLine += fmt.Sprintf(", served=upstream:%s", fastest)
	elapsed := time.Since(start)
	ms := float64(elapsed.Nanoseconds()) / 1e6
	logLine += fmt.Sprintf(", proto=%s, time=%.3fms", protocol, ms)

	// Print once, in one line
	log.Println(logLine)
	fileLogger.Println(logLine)

	return resp, fastest, nil
}

// filterAAAAIfAExists checks for an A record for the queried domain and,
// if found, removes any AAAA records from the response.
func filterAAAAIfAExists(resp *dns.Msg, req *dns.Msg, remoteAddr, proto string, reqID uint64, start time.Time) *dns.Msg {
	// Only apply if the query is AAAA and the CLI flag is set.
	if len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeAAAA || !denyAAAA {
		return resp
	}

	// Create a new A query for the same domain.
	aReq := new(dns.Msg)
	aReq.SetQuestion(req.Question[0].Name, dns.TypeA)
	// Increment the global request counter for this additional lookup.
	newReqID := atomic.AddUint64(&globalReqCount, 1)
	aResp, _, err := resolveDNS(remoteAddr, proto, aReq, newReqID, start)
	if err == nil && len(aResp.Answer) > 0 {
		// Log that we are denying AAAA records because an A record exists.
		logLine := fmt.Sprintf("reqID=%d, domain=%s: AAAA response denied because A record exists", reqID, req.Question[0].Name)
		log.Println(logLine)
		fileLogger.Println(logLine)

		// Remove any AAAA records from the Answer section.
		var filteredAnswers []dns.RR
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype != dns.TypeAAAA {
				filteredAnswers = append(filteredAnswers, rr)
			}
		}
		resp.Answer = filteredAnswers

		// Similarly, filter out AAAA records from the Extra section.
		var filteredExtra []dns.RR
		for _, rr := range resp.Extra {
			if rr.Header().Rrtype != dns.TypeAAAA {
				filteredExtra = append(filteredExtra, rr)
			}
		}
		resp.Extra = filteredExtra
	}
	return resp
}

// handleDNSRequest is the handler for DNS queries (used by UDP/TCP servers).
func handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	// Increment the global request counter.
	reqID := atomic.AddUint64(&globalReqCount, 1)

	remoteAddr := w.RemoteAddr().String()
	// Determine protocol based on the underlying connection type.
	var proto string
	switch w.RemoteAddr().(type) {
	case *net.UDPAddr:
		proto = "udp53"
	case *net.TCPAddr:
		proto = "tcp53"
	default:
		proto = "unknown"
	}

	resp, _, err := resolveDNS(remoteAddr, proto, req, reqID, start)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// If this is a AAAA query and the denyAAAA flag is enabled, check for an A record.
	if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeAAAA && denyAAAA {
		resp = filterAAAAIfAExists(resp, req, remoteAddr, proto, reqID, start)
	}

	_ = w.WriteMsg(resp)
}

// dohHandler implements a simple DNS-over-HTTPS (DoH) endpoint.
func dohHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := atomic.AddUint64(&globalReqCount, 1)

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
	proto := "http"
	resp, _, err := resolveDNS(remoteAddr, proto, &reqMsg, reqID, start)
	if err != nil {
		http.Error(w, "DNS query failed", http.StatusInternalServerError)
		return
	}

	// If this is a AAAA query and the denyAAAA flag is enabled, check for an A record.
	if len(reqMsg.Question) > 0 && reqMsg.Question[0].Qtype == dns.TypeAAAA && denyAAAA {
		resp = filterAAAAIfAExists(resp, &reqMsg, remoteAddr, proto, reqID, start)
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
	// Define the CLI flag.
	denyAAAAFlag := flag.Bool("denyAAAA", true, "Deny IPv6 AAAA records if an A record for the domain exists")
	expireMultiplierFlag := flag.Int("expireMultiplier", 10, "Multiplier for the cache expiration time")
	flag.Parse()
	denyAAAA = *denyAAAAFlag
	EXPIRE_MULTIPLIER  = *expireMultiplierFlag

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
