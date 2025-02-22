package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"crypto/tls"
	"math/rand"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
	"golang.org/x/net/proxy"
)

var EXPIRE_MULTIPLIER int
var requestGroup singleflight.Group
var upstreamTimeoutSeconds = time.Duration(3) * time.Second

// Global counters.
var globalReqCount uint64
var globalFailedCount uint64
var globalCacheHits uint64
var globalDeniedAAAA uint64
var globalChinaDomainsCount uint64
var globalDefaultDomainsDNSCount uint64

// globalRRCount records the number of records served by type (A, AAAA, MX, CNAME, etc.).
var globalRRCount = make(map[string]uint64)
var globalRRCountMutex sync.Mutex

// persistentCacheEntry is the structure we use to save the cache to disk.
type persistentCacheEntry struct {
	Key         string `json:"key"`
	Msg         string `json:"msg"` // base64 encoded dns message bytes
	Expires     int64  `json:"expires"`
	OriginalTTL uint32 `json:"original_ttl"`
	Created     int64  `json:"created"`
}

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

// Config holds our custom configuration loaded from JSON.
type Config struct {
	SocksServers    []string  `json:"socks_servers"`
	UpstreamsChina  []Upstream `json:"upstreams_china"`
	UpstreamsDefault []Upstream `json:"upstreams_default"`
	ChinaListFilterKeywords []string `json:"china_list_filter_keywords"`
}

// Global configuration variables.
var (
	socksServers    []string
	upstreamsChina  []Upstream
	upstreamsDefault []Upstream
	chinaListFilterKeywords []string
)

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

// denyAAAA is set via CLI flag; when true, AAAA answers will be removed if an A record exists.
var denyAAAA bool

// chinaList holds the domains/subdomains loaded from chinalist.txt.
var chinaList map[string]bool

// Enforce a minimum TTL so zero/low TTLs from upstream won't disable caching.
const defaultMinTTL = 30

// Name of the file used for persistent cache.
const cacheFile = "cache_db.json"

// ANSI color codes
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorBlue   = "\033[34m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"	
)

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

// httpRequestWithSockServers makes an HTTP GET request to the provided URL,
// ignoring TLS certificate verification. If httpsUseSocks is true, it routes the request
// through a SOCKS5 proxy. It returns the response body as a byte slice.
func httpRequestWithSockServers(url string, httpsUseSocks bool) ([]byte, error) {
	var client *http.Client

	if httpsUseSocks {
		// Define the SOCKS5 proxy address.
		//socksAddr := "127.0.0.1:1080" // Update this with your SOCKS proxy address if needed.
		//random select socks server
		socksAddr := socksServers[rand.Intn(len(socksServers))]

		// Create a SOCKS5 dialer.
		dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		// Set up a transport that uses the SOCKS5 dialer and ignores certificate checks.
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Dial:            dialer.Dial,
		}

		client = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
	} else {
		// Set up a transport that ignores certificate checks.
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
	}

	// Perform the GET request.
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make GET request: %w", err)
	}
	defer resp.Body.Close()

	// Check for a non-OK HTTP status.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-OK HTTP status: %s", resp.Status)
	}

	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}


// queryUpstreams sends the DNS query concurrently to the provided upstream servers and returns the fastest reply.
func queryUpstreams(req *dns.Msg, ups []Upstream) (*dns.Msg, string, error) {
	respCh := make(chan upstreamResponse, len(ups))
	httpsUseSocks := true
	// Launch queries concurrently.
	for _, u := range ups {
		go func(u Upstream) {
			if u.Protocol == "https" { // DNS-over-HTTPS.
				packed, err := req.Pack()
				url := u.Address + "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
				body, err := httpRequestWithSockServers(url, httpsUseSocks)
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

	totalUpstreams := len(ups)
	responsesReceived := 0
	var candidate upstreamResponse
	foundCandidate := false

	// Overall timeout for upstream responses.
	overallTimeout := time.NewTimer(upstreamTimeoutSeconds * time.Second)
	defer overallTimeout.Stop()

	// Wait for the first successful response.
	for responsesReceived < totalUpstreams {
		select {
		case resp := <-respCh:
			responsesReceived++
			if resp.err != nil || resp.msg == nil {
				continue
			}
			candidate = resp
			foundCandidate = true
			break
		case <-overallTimeout.C:
			return nil, "", errors.New("upstream query timed out")
		}
		if foundCandidate {
			break
		}
	}

	if !foundCandidate {
		// In case no successful response was received.
		return nil, "", errors.New("all upstream queries failed")
	}

	// If the first successful response is IPv4, return it immediately.
	if candidate.IsIPv4 {
		return candidate.msg, candidate.Source, nil
	}

	// Otherwise, wait briefly for an IPv4 answer.
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
	//filter the filename by the china_list_filter_keywords
	
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
	log.Printf("Chinalist filter number of words %d", len(chinaListFilterKeywords))
	var filteredCount int
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
		for _, keyword := range chinaListFilterKeywords {
			if strings.Contains(domain, keyword) {
				delete(m, domain)
				filteredCount++
				break
			}
		}
	}
	log.Printf("Filtered out Chinalist domains: %d", filteredCount)
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// recordRRCounts iterates through all sections of the DNS response and updates global counters per record type.
func recordRRCounts(msg *dns.Msg) {
	globalRRCountMutex.Lock()
	defer globalRRCountMutex.Unlock()
	for _, rr := range msg.Answer {
		rtype := dns.TypeToString[rr.Header().Rrtype]
		globalRRCount[rtype]++
	}
	for _, rr := range msg.Ns {
		rtype := dns.TypeToString[rr.Header().Rrtype]
		globalRRCount[rtype]++
	}
	for _, rr := range msg.Extra {
		rtype := dns.TypeToString[rr.Header().Rrtype]
		globalRRCount[rtype]++
	}
}

// resolveDNS handles caching, upstream querying, and logging. It selects the upstream servers
// based on whether the queried domain (or its parent) is in the China list.
func resolveDNS(remoteAddr, protocol string, req *dns.Msg, reqID uint64, start time.Time) (*dns.Msg, string, error) {
	domain := ""
	if len(req.Question) > 0 {
		domain = req.Question[0].Name
	}
	// Build a log line.
	logLine := fmt.Sprintf("[%d], remote=%s, domain=%s", reqID, remoteAddr, domain)

	key := cacheKey(req)
	// Check cache.
	if cachedMsg, found := getCachedResponse(key); found {
		// Count a cache hit.
		atomic.AddUint64(&globalCacheHits, 1)
		cachedMsg.Id = req.Id
		logLine += ", served=cache"
		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		logLine += fmt.Sprintf(", from=%s, time=%.3fms", protocol, ms)
		logLine = "HIT: " + logLine
		fmt.Printf("%s%s%s\n", colorGreen, logLine, colorReset)
		fileLogger.Println(logLine)
		return cachedMsg, "cache", nil
	}

	// Choose upstreams and set color.
	var selectedUpstreams []Upstream
	var color string
	if isChinaDomain(domain) {
		selectedUpstreams = upstreamsChina
		logLine += ", upstream=china"
		logLine = "CHN: " + logLine
		color = colorBlue
		atomic.AddUint64(&globalChinaDomainsCount, 1)
	} else {
		selectedUpstreams = upstreamsDefault
		logLine += ", upstream=default"
		logLine = "DFT: " + logLine
		color = colorYellow
		atomic.AddUint64(&globalDefaultDomainsDNSCount, 1)
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
		logLine = "FAILED: " + logLine
		logLine += fmt.Sprintf(", error=%v", err)
		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		logLine += fmt.Sprintf(", proto=%s, time=%.3fms", protocol, ms)
		fmt.Printf("%s%s%s\n", colorRed, logLine, colorReset)
		fileLogger.Println(logLine)
		atomic.AddUint64(&globalFailedCount, 1)
		return nil, "", err
	}

	result := v.(upstreamResult)
	elapsed := time.Since(start)
	ms := float64(elapsed.Nanoseconds()) / 1e6
	logLine += fmt.Sprintf(", served=upstream:%s, proto=%s, time=%.3fms", result.fastest, protocol, ms)
	fmt.Printf("%s%s%s\n", color, logLine, colorReset)
	fileLogger.Println(logLine)
	return result.msg, result.fastest, nil
}

// filterAAAAIfAExists checks for an A record for the queried domain and,
// if found, returns an NXDOMAIN response (empty AAAA answer) with a root SOA.
func filterAAAAIfAExists(resp *dns.Msg, req *dns.Msg, remoteAddr, proto string, reqID uint64, start time.Time) *dns.Msg {
	if len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeAAAA || !denyAAAA {
		return resp
	}
	var emptyResp = true

	if emptyResp {
		resp.Answer = nil
		resp.Extra = nil
		return resp
	}else{
		aReq := new(dns.Msg)
		aReq.SetQuestion(req.Question[0].Name, dns.TypeA)
		newReqID := atomic.AddUint64(&globalReqCount, 1)
		aResp, _, err := resolveDNS(remoteAddr, proto, aReq, newReqID, start)
		if err == nil && len(aResp.Answer) > 0 {
			atomic.AddUint64(&globalDeniedAAAA, 1)
			logLine := fmt.Sprintf("[%d] domain=%s: Returning NXDOMAIN for AAAA query because A record exists", reqID, req.Question[0].Name)
			fileLogger.Println(logLine)
			log.Printf(logLine)

			// Build a new response message with NXDOMAIN (RcodeNameError)
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeNameError)
			// Add a static root SOA record in the authority section.
			soa, err := dns.NewRR(". 86399 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2025021902 1800 900 604800 86400")
			if err == nil {
				m.Ns = []dns.RR{soa}
			}
			// Optionally, add an OPT record for EDNS0.
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetUDPSize(4096)
			m.Extra = []dns.RR{opt}
			return m
		}
		return resp
	}
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

	// Record the DNS record counts from this response.
	recordRRCounts(resp)

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

	// Record the record counts for this response.
	recordRRCounts(resp)

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

// printCacheStats prints statistics about the cache every 10 seconds.
func printCacheStats() {
	startTime := time.Now()
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		now := time.Now()
		cacheMutex.RLock()
		total := len(cache)
		expired := 0
		valid := 0
		for _, entry := range cache {
			if now.After(entry.expires) {
				expired++
			} else {
				valid++
			}
		}
		cacheMutex.RUnlock()

		// Uptime formatting: if less than 1 day, show hours/minutes/seconds.
		uptime := now.Sub(startTime)
		days := int(uptime.Hours()) / 24
		var uptimeStr string
		if days > 0 {
			uptimeStr = fmt.Sprintf("%d D, %d H, %d M", days, int(uptime.Hours())%24, int(uptime.Minutes())%60)
		} else {
			uptimeStr = fmt.Sprintf("%d H, %d M, %d S", int(uptime.Hours()), int(uptime.Minutes())%60, int(uptime.Seconds())%60)
		}

		requests := atomic.LoadUint64(&globalReqCount)
		requestsPerSecond := float64(requests) / uptime.Seconds()
		cacheHits := atomic.LoadUint64(&globalCacheHits)
		chinaDomainsCount := atomic.LoadUint64(&globalChinaDomainsCount)
		defaultDomainsCount := atomic.LoadUint64(&globalDefaultDomainsDNSCount)

		var cacheHitRate float64
		if requests > 0 {
			cacheHitRate = float64(cacheHits) / float64(requests) * 100
		}
		failed := atomic.LoadUint64(&globalFailedCount)
		deniedAAAA := atomic.LoadUint64(&globalDeniedAAAA)

		banner := fmt.Sprintf("==========Cache Stats | Uptime: %s==========", uptimeStr)
		fmt.Println(banner)
		fmt.Printf("%sTotal Cache Entries=%d, Valid=%d, Expired=%d, Failed=%d, DeniedAAAA=%d%s\n", colorCyan, total, valid, expired, failed, deniedAAAA, colorReset)
		fmt.Printf("%sTotal DNS Requests=%d, ReqPerSec=%.2f, Cache Hit Rate=%.2f%%, Cache Miss Rate=%.2f%%%s\n", colorCyan, requests, requestsPerSecond, cacheHitRate, 100-cacheHitRate, colorReset)
		fmt.Printf("%sRequest China Domains=%d, %sRequest Default Domains=%d%s\n", colorBlue, chinaDomainsCount, colorYellow, defaultDomainsCount, colorReset)

		// Print the counts per record type.
		globalRRCountMutex.Lock()
		fmt.Printf("%sDNS Record Type Counts:", colorCyan)
		for rtype, count := range globalRRCount {
			fmt.Printf(" %s=%d", rtype, count)
		}
		fmt.Printf("%s\n", colorReset)
		globalRRCountMutex.Unlock()

		fmt.Println(strings.Repeat("=", len(banner)))
	}
}

// saveCacheToDisk writes the current cache to a file (in JSON format).
func saveCacheToDisk(filename string) error {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	var entries []persistentCacheEntry
	for key, entry := range cache {
		packed, err := entry.msg.Pack()
		if err != nil {
			log.Printf("Failed to pack dns msg for key %s: %v", key, err)
			continue
		}
		encodedMsg := base64.StdEncoding.EncodeToString(packed)
		entries = append(entries, persistentCacheEntry{
			Key:         key,
			Msg:         encodedMsg,
			Expires:     entry.expires.Unix(),
			OriginalTTL: entry.originalTTL,
			Created:     entry.created.Unix(),
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// loadCacheFromDisk loads the cache from the given file.
func loadCacheFromDisk(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var entries []persistentCacheEntry
	err = json.Unmarshal(data, &entries)
	if err != nil {
		return err
	}
	now := time.Now()
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	for _, entry := range entries {
		if now.Unix() > entry.Expires {
			// Skip expired entries.
			continue
		}
		packed, err := base64.StdEncoding.DecodeString(entry.Msg)
		if err != nil {
			log.Printf("Failed to decode msg for key %s: %v", entry.Key, err)
			continue
		}
		var msg dns.Msg
		err = msg.Unpack(packed)
		if err != nil {
			log.Printf("Failed to unpack dns msg for key %s: %v", entry.Key, err)
			continue
		}
		cache[entry.Key] = cacheEntry{
			msg:         &msg,
			expires:     time.Unix(entry.Expires, 0),
			originalTTL: entry.OriginalTTL,
			created:     time.Unix(entry.Created, 0),
		}
	}
	return nil
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
	//print date and welcome message
	log.Println("\033[32m" + time.Now().Format("2006-01-02 15:04:05") + " Welcome to c2dns" + "\033[0m")
	denyAAAAFlag := flag.Bool("denyAAAA", true, "Deny IPv6 AAAA records if an A record exists")
	expireMultiplierFlag := flag.Int("expireMultiplier", 10, "Multiplier for the cache expiration time")
	chinaListFile := flag.String("chinaList", "chinalist.txt", "Path to the China list file")
	configFile := flag.String("config", "config.json", "Path to the configuration JSON file")
	flag.Parse()
	denyAAAA = *denyAAAAFlag
	EXPIRE_MULTIPLIER = *expireMultiplierFlag

	// Load the configuration.
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configFile, err)
	}
	socksServers = cfg.SocksServers
	upstreamsChina = cfg.UpstreamsChina
	upstreamsDefault = cfg.UpstreamsDefault
	chinaListFilterKeywords = cfg.ChinaListFilterKeywords

	// Load the China list.
	chinaList, err = loadChinaList(*chinaListFile)
	if err != nil {
		// Attempt to download from an alternative URL.
		chinaList, err = loadChinaList("https://raw.githubusercontent.com/pexcn/openwrt-chinadns-ng/refs/heads/master/files/chinalist.txt")
		if err != nil {
			log.Fatalf("Failed to load China list: %v", err)
			os.Exit(1)
		} else {
			log.Printf("Downloaded %d entries from the remote China list", len(chinaList))
		}
	} else {
		log.Printf("Loaded %d entries from %s", len(chinaList), *chinaListFile)
	}
	
	// Attempt to load the persistent cache.
	if _, err := os.Stat(cacheFile); err == nil {
		err = loadCacheFromDisk(cacheFile)
		if err != nil {
			log.Printf("Failed to load cache: %v", err)
		} else {
			log.Println("Cache loaded successfully.")
		}
	}

	// Open (or create) a log file.
	f, err := os.OpenFile("dns_queries.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	fileLogger = log.New(f, "", log.LstdFlags)

	// Set up a signal handler to save the cache on shutdown.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, saving cache...")
		if err := saveCacheToDisk(cacheFile); err != nil {
			log.Printf("Failed to save cache: %v", err)
		} else {
			log.Println("Cache saved successfully.")
		}
		os.Exit(0)
	}()

	go printCacheStats()

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
