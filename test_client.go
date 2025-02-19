package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// ANSI color codes
const (
	green = "\033[32m"
	red   = "\033[31m"
	blue  = "\033[34m"
	reset = "\033[0m"
)

// makeDNSQueryMsg creates a DNS query message for a given domain and query type.
func makeDNSQueryMsg(domain string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	return m
}

// queryUDP queries the local DNS server via UDP on port 53.
func queryUDP(domain string) error {
	fmt.Println("=== Querying via UDP ===")
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 2 * time.Second

	msg := makeDNSQueryMsg(domain, dns.TypeA)

	start := time.Now()
	r, rtt, err := c.Exchange(msg, "127.0.0.1:53")
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("UDP query error: %v\n", err)
		fmt.Printf("%sUDP total time used: %v%s\n\n", blue, elapsed, reset)
		return err
	}

	fmt.Printf("UDP RTT (dns.Client reported): %v\n", rtt)
	fmt.Printf("%sUDP total time used: %v%s\n", blue, elapsed, reset)
	fmt.Printf("UDP Response:\n%v\n\n", r)
	return nil
}

// queryTCP queries the local DNS server via TCP on port 53.
func queryTCP(domain string) error {
	fmt.Println("=== Querying via TCP ===")
	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = 2 * time.Second

	msg := makeDNSQueryMsg(domain, dns.TypeA)

	start := time.Now()
	r, rtt, err := c.Exchange(msg, "127.0.0.1:53")
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("TCP query error: %v\n", err)
		fmt.Printf("%sTCP total time used: %v%s\n\n", blue, elapsed, reset)
		return err
	}

	fmt.Printf("TCP RTT (dns.Client reported): %v\n", rtt)
	fmt.Printf("%sTCP total time used: %v%s\n", blue, elapsed, reset)
	fmt.Printf("TCP Response:\n%v\n\n", r)
	return nil
}

// queryDoH queries the local DNS server via DoH (GET) on http://127.0.0.1:8080/dns-query.
func queryDoH(domain string) error {
	fmt.Println("=== Querying via DoH (HTTP GET) ===")

	msg := makeDNSQueryMsg(domain, dns.TypeA)
	packed, err := msg.Pack()
	if err != nil {
		log.Printf("DoH pack error: %v\n", err)
		return err
	}

	encoded := base64.RawURLEncoding.EncodeToString(packed)
	url := "http://127.0.0.1:8080/dns-query?dns=" + encoded

	client := &http.Client{Timeout: 3 * time.Second}

	start := time.Now()
	resp, err := client.Get(url)
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("DoH GET error: %v\n", err)
		fmt.Printf("%sDoH total time used: %v%s\n\n", blue, elapsed, reset)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("DoH non-OK status: %d", resp.StatusCode)
		log.Println(err)
		fmt.Printf("%sDoH total time used: %v%s\n\n", blue, elapsed, reset)
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("DoH read error: %v\n", err)
		fmt.Printf("%sDoH total time used: %v%s\n\n", blue, elapsed, reset)
		return err
	}

	var dohMsg dns.Msg
	if err = dohMsg.Unpack(body); err != nil {
		log.Printf("DoH unpack error: %v\n", err)
		fmt.Printf("%sDoH total time used: %v%s\n\n", blue, elapsed, reset)
		return err
	}

	fmt.Printf("%sDoH total time used: %v%s\n", blue, elapsed, reset)
	fmt.Println("DoH Response:")
	fmt.Println(&dohMsg)
	fmt.Println()
	return nil
}

func main() {
	domain := "baidu.com"

	// We'll track how many of the 3 tests pass.
	total := 3
	passed := 0

	// 1) Test UDP
	if err := queryUDP(domain); err == nil {
		passed++
	}
	// 2) Test TCP
	if err := queryTCP(domain); err == nil {
		passed++
	}
	// 3) Test DoH
	if err := queryDoH(domain); err == nil {
		passed++
	}

	// Print final result with color.
	if passed == total {
		fmt.Printf("%s%d/%d tests passed%s\n", green, passed, total, reset)
	} else {
		fmt.Printf("%s%d/%d tests passed%s\n", red, passed, total, reset)
	}
}
