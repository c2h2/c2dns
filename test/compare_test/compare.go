package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

// DomainResult holds the query result for one domain.
type DomainResult struct {
	Domain       string
	AuthIPs      []string
	TestIPs      []string
	AuthLatency  time.Duration
	TestLatency  time.Duration
	AuthSuccess  bool
	TestSuccess  bool
	AuthError    error
	TestError    error
}

// queryARecord sends a DNS query for A records to a server.
func queryARecord(domain, server string) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	client := new(dns.Client)
	client.Timeout = 5 * time.Second
	start := time.Now()
	resp, _, err := client.Exchange(m, server)
	latency := time.Since(start)
	return resp, latency, err
}

// queryARecordWithRetry wraps queryARecord and retries up to retries times if a timeout occurs.
func queryARecordWithRetry(domain, server string, retries int) (*dns.Msg, time.Duration, error) {
	var totalLatency time.Duration
	for i := 0; i < retries; i++ {
		resp, latency, err := queryARecord(domain, server)
		totalLatency += latency
		if err != nil {
			// Check if error is a timeout.
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				// Retry on timeout.
				continue
			}
			return nil, totalLatency, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return resp, totalLatency, fmt.Errorf("non-success Rcode=%d", resp.Rcode)
		}
		return resp, totalLatency, nil
	}
	return nil, totalLatency, fmt.Errorf("timeout after %d retries", retries)
}

// extractARecords returns a sorted slice of A record IP strings from a DNS response.
func extractARecords(resp *dns.Msg) []string {
	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	sort.Strings(ips)
	return ips
}

// processDomain queries both authority (1.1.1.1) and test (192.168.8.8) servers.
func processDomain(domain string) DomainResult {
	const maxRetries = 3
	var res DomainResult
	res.Domain = domain

	// Query authority server.
	authServer := "8.8.8.8:53"
	authResp, authLatency, err := queryARecordWithRetry(domain, authServer, maxRetries)
	res.AuthLatency = authLatency
	if err != nil {
		res.AuthSuccess = false
		res.AuthError = err
	} else {
		res.AuthSuccess = true
		res.AuthIPs = extractARecords(authResp)
	}

	// Query test server.
	testServer := "192.168.8.8:53"
	testResp, testLatency, err := queryARecordWithRetry(domain, testServer, maxRetries)
	res.TestLatency = testLatency
	if err != nil {
		res.TestSuccess = false
		res.TestError = err
	} else {
		res.TestSuccess = true
		res.TestIPs = extractARecords(testResp)
	}

	return res
}

func main() {
	fileName := flag.String("file", "domains.txt", "File containing domains (one per line)")
	flag.Parse()

	// Read domains from file.
	f, err := os.Open(*fileName)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			domains = append(domains, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Set up worker pool.
	domainChan := make(chan string, len(domains))
	resultChan := make(chan DomainResult, len(domains))
	var wg sync.WaitGroup
	const workerCount = 5

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range domainChan {
				resultChan <- processDomain(d)
			}
		}()
	}

	for _, d := range domains {
		domainChan <- d
	}
	close(domainChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and print colored output.
	var total, success, mismatch, failed int
	var totalLatency time.Duration
	for res := range resultChan {
		// If one of the queries failed.
		if !res.AuthSuccess || !res.TestSuccess {
			failed++
			fmt.Printf("%sDomain: %-30s FAILED%s\n", colorRed, res.Domain, colorReset)
			if !res.AuthSuccess {
				fmt.Printf("%s  Authority error: %v%s\n", colorRed, res.AuthError, colorReset)
			}
			if !res.TestSuccess {
				fmt.Printf("%s  Test error: %v%s\n", colorRed, res.TestError, colorReset)
			}
			continue
		}

		// Both queries succeeded. Compare answers.
		authStr := strings.Join(res.AuthIPs, ",")
		testStr := strings.Join(res.TestIPs, ",")
		if authStr == testStr {
			success++
			totalLatency += res.TestLatency
			fmt.Printf("%sDomain: %-30s SUCCESS | Latency: %v | IPs: %v%s\n", colorGreen, res.Domain, res.TestLatency, res.TestIPs, colorReset)
		} else {
			mismatch++
			fmt.Printf("%sDomain: %-30s MISMATCH%s\n", colorYellow, res.Domain, colorReset)
			fmt.Printf("%s  Authority IPs: %v%s\n", colorYellow, res.AuthIPs, colorReset)
			fmt.Printf("%s  Test IPs:      %v%s\n", colorYellow, res.TestIPs, colorReset)
		}
		total++
	}

	// Print summary.
	fmt.Println("--------- Summary ---------")
	fmt.Printf("Total domains: %d\n", total)
	fmt.Printf("%sSuccess:       %d%s\n", colorGreen, success, colorReset)
	fmt.Printf("%sMismatch:      %d%s\n", colorYellow, mismatch, colorReset)
	fmt.Printf("%sFailed:        %d%s\n", colorRed, failed, colorReset)
	if success > 0 {
		avgLatency := totalLatency / time.Duration(success)
		fmt.Printf("Average test latency: %v\n", avgLatency)
	}
}
