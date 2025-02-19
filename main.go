package main

import (
	"bufio"
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
	"golang.org/x/sync/singleflight"
)

var EXPIRE_MULTIPLIER int
var requestGroup singleflight.Group

// upstreamResult holds the result from an upstream query.
type upstreamResult struct {
	msg     *dns.Msg
	fastest string
}

// Upstream represents an upstream DNS server.
type Upstream struct {
	Address  string // For UDP/TCP: host:port; For HTTPS: full URL (e.g. "https://1.1.1.1/dns-query")
	IsIPv4   bool   // whether this upstream is IPv4
	Protocol string // "udp", "tcp", or "https"
}

// upstreamsChina is used for domains in the China list.
var upstreamsChina = []Upstream{
	{Address: "223.5.5.5:53", IsIPv4: true, Protocol: "udp"},
	{Address: "223.6.6.6:53", IsIPv4: true, Protocol: "udp"},
}

// upstreamsDefault is used for other domains.
var upstreamsDefault = []Upstream{
	{Address: "1.1.1.1:53", IsIPv4: true, Protocol: "udp"},
	{Address: "8.8.8.8:53", IsIPv4: true, Protocol: "udp"},
	{Address: "8.8.4.4:53", IsIPv4: true, Protocol: "udp"},
	{Address: "9.9.9.9:53", IsIPv4: true, Protocol: "udp"},
	// DNS-over-HTTPS example:
	{Address: "https://1.1.1.1/dns-query", IsIPv4: true, Protocol: "https"},
	{Address: "https://8.8.8.8/dns-query", IsIPv4: true, Protocol: "https"},
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

	// fileLogger logs query details to a file.
	fileLogger *log.Logger
)

// globalReqCount is a counter for all requests.
var globalReqCount uint64

// denyAAAA is set via CLI flag; when true, AAAA answers will be removed if an A record exists.
var denyAAAA bool

// chinaList holds the domains/subdomains loaded from chinalist.txt.
var chinaList map[string]bool

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
		// Expired—remove from cache.
		cacheMutex.Lock()
		delete(cache, key)
		cacheMutex.Unlock()
		return nil, false
	}

	// Calculate remaining TTL (in seconds).
	remainingSecs := uint32(entry.expires.Sub(now).Seconds())

	// Create a copy and update TTL values.
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

	// Find the minimum TTL in Answer, Ns, and Extra.
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

	if minTTL == 0xffffffff {
		minTTL = 60
	} else if minTTL < defaultMinTTL {
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
}

// queryUpstreams sends the DNS query concurrently to the provided upstream servers and returns the fastest reply.
func queryUpstreams(req *dns.Msg, ups []Upstream) (*dns.Msg, string, error) {
	respCh := make(chan upstreamResponse, len(ups))

	// Launch queries concurrently.
	for _, u := range ups {
		go func(u Upstream) {
			if u.Protocol == "https" {
				// DNS-over-HTTPS logic.
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
				// UDP/TCP exchange.
				client := new(dns.Client)
				client.Net = u.Protocol
				r, _, err := client.Exchange(req, u.Address)
				respCh <- upstreamResponse{msg: r, IsIPv4: u.IsIPv4, Source: u.Address, err: err}
			}
		}(u)
	}

	total := len(ups)
	responsesReceived := 0
	var candidate upstreamResponse
	foundCandidate := false

	// Wait for the first successful response.
	for responsesReceived < total {
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
		//wait for all upstreams to finish
		for range ups {
			<-respCh
		}
		if !foundCandidate {
			return nil, "", errors.New("all upstream queries failed")
		}
	}

	// If the first successful response is IPv4, return it immediately.
	if candidate.IsIPv4 {
		return candidate.msg, candidate.Source, nil
	}

	// Otherwise, wait briefly for an IPv4 answer.
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()

	for responsesReceived < total {
		select {
		case resp := <-respCh:
			responsesReceived++
			if resp.err != nil || resp.msg == nil {
				continue
			}
			if resp.IsIPv4 {
				candidate = resp
				return candidate.msg, candidate.Source, nil
			}
		case <-timer.C:
			return candidate.msg, candidate.Source, nil
		}
	}

	return candidate.msg, candidate.Source, nil
}

// isChinaDomain checks whether the given domain (or one of its parent domains) is in the China list.
func isChinaDomain(domain string) bool {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	parts := strings.Split(d, ".")
	// Check each possible suffix.
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if chinaList[candidate] {
			return true
		}
	}
	return false
}

// loadChinaList reads domains from the specified file (or URL) into a map.
func loadChinaList(filename string) (map[string]bool, error) {
	var reader io.Reader

	if strings.HasPrefix(filename, "http") {
		// Download from URL.
		log.Printf("Downloading China list from %s", filename)
		resp, err := http.Get(filename)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		reader = resp.Body
	} else {
		// Open local file.
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		reader = f
	}

	m := make(map[string]bool)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Normalize the domain: lower-case and remove trailing dot.
		domain := strings.TrimSuffix(strings.ToLower(line), ".")
		m[domain] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// resolveDNS handles caching, upstream querying, and logging. It selects the upstream servers
// based on whether the queried domain (or its parent) is in the China list.
func resolveDNS(remoteAddr, protocol string, req *dns.Msg, reqID uint64, start time.Time) (*dns.Msg, string, error) {
	domain := ""
	if len(req.Question) > 0 {
		domain = req.Question[0].Name
	}
	// Build a log line.
	logLine := fmt.Sprintf("reqID=%d, remote=%s, domain=%s", reqID, remoteAddr, domain)

	key := cacheKey(req)
	// Check cache.
	if cachedMsg, found := getCachedResponse(key); found {
		cachedMsg.Id = req.Id
		logLine += ", served=cache"
		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		logLine += fmt.Sprintf(", from=%s, time=%.3fms", protocol, ms)
		log.Println(logLine)
		fileLogger.Println(logLine)
		return cachedMsg, "cache", nil
	}

	// Choose upstreams.
	var selectedUpstreams []Upstream
	if isChinaDomain(domain) {
		selectedUpstreams = upstreamsChina
		logLine += ", upstream=china"
	} else {
		selectedUpstreams = upstreamsDefault
		logLine += ", upstream=default"
	}

	// Use singleflight to collapse duplicate in-flight queries.
	v, err, _ := requestGroup.Do(key, func() (interface{}, error) {
		resp, fastest, err := queryUpstreams(req, selectedUpstreams)
		if err != nil {
			return nil, err
		}
		resp.Id = req.Id
		// Cache the response.
		setCache(key, resp)
		return upstreamResult{msg: resp, fastest: fastest}, nil
	})

	if err != nil {
		logLine += fmt.Sprintf(", error=%v", err)
		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		logLine += fmt.Sprintf(", proto=%s, time=%.3fms", protocol, ms)
		log.Println(logLine)
		fileLogger.Println(logLine)
		return nil, "", err
	}

	result := v.(upstreamResult)
	elapsed := time.Since(start)
	ms := float64(elapsed.Nanoseconds()) / 1e6
	logLine += fmt.Sprintf(", served=upstream:%s, proto=%s, time=%.3fms", result.fastest, protocol, ms)
	log.Println(logLine)
	fileLogger.Println(logLine)
	return result.msg, result.fastest, nil
}

// filterAAAAIfAExists checks for an A record for the queried domain and, if found,
// removes any AAAA records from the response.
func filterAAAAIfAExists(resp *dns.Msg, req *dns.Msg, remoteAddr, proto string, reqID uint64, start time.Time) *dns.Msg {
	if len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeAAAA || !denyAAAA {
		return resp
	}

	aReq := new(dns.Msg)
	aReq.SetQuestion(req.Question[0].Name, dns.TypeA)
	newReqID := atomic.AddUint64(&globalReqCount, 1)
	aResp, _, err := resolveDNS(remoteAddr, proto, aReq, newReqID, start)
	if err == nil && len(aResp.Answer) > 0 {
		logLine := fmt.Sprintf("reqID=%d, domain=%s: AAAA response denied because A record exists", reqID, req.Question[0].Name)
		//log.Println(logLine)
		fileLogger.Println(logLine)

		var filteredAnswers []dns.RR
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype != dns.TypeAAAA {
				filteredAnswers = append(filteredAnswers, rr)
			}
		}
		resp.Answer = filteredAnswers

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

// handleDNSRequest is the handler for DNS queries (UDP/TCP).
func handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	reqID := atomic.AddUint64(&globalReqCount, 1)
	remoteAddr := w.RemoteAddr().String()

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

	// If it's a AAAA query and denyAAAA is enabled, filter out AAAA answers if an A record exists.
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

	if len(reqMsg.Question) > 0 && reqMsg.Question[0].Qtype == dns.TypeAAAA && denyAAAA {
		resp = filterAAAAIfAExists(resp, &reqMsg, remoteAddr, proto, reqID, start)
	}

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
	denyAAAAFlag := flag.Bool("denyAAAA", true, "Deny IPv6 AAAA records if an A record exists")
	expireMultiplierFlag := flag.Int("expireMultiplier", 10, "Multiplier for the cache expiration time")
	chinaListFile := flag.String("chinaList", "chinalist.txt", "Path to the China list file")
	flag.Parse()
	denyAAAA = *denyAAAAFlag
	EXPIRE_MULTIPLIER = *expireMultiplierFlag

	// Load the China list.
	var err error
	chinaList, err = loadChinaList(*chinaListFile)
	if err != nil {
		//log.Fatalf("Failed to load China list: %v", err)
		//download from https://raw.githubusercontent.com/pexcn/openwrt-chinadns-ng/refs/heads/master/files/chinalist.txt
		chinaList, err = loadChinaList("https://raw.githubusercontent.com/pexcn/openwrt-chinadns-ng/refs/heads/master/files/chinalist.txt")
		if err != nil {
			log.Fatalf("Failed to load China list: %v", err)
			os.Exit(1)
		} else {
			log.Printf("Downloaded %d entries from %s")
		}
	} else {
		log.Printf("Loaded %d entries from %s", len(chinaList), *chinaListFile)
	}


	// Open (or create) a log file.
	f, err := os.OpenFile("dns_queries.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	fileLogger = log.New(f, "", log.LstdFlags)

	// Set up DNS handlers (UDP and TCP).
	dns.HandleFunc(".", handleDNSRequest)

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
