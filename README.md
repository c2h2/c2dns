# c<sup>2</sup>dns

c<sup>2</sup>dns is a lightspeed, lightweight DNS resolver in Go. c2dns 是一个Go的轻量化、高速 DNS 解析器 🚀

- **Multi-Port Support**: Listens on TCP/UDP port 53 and HTTP port 8080, with upstream support for TCP, UDP, HTTP, and HTTPS.
- **China List Routing**: Domains specified in `chinalist.txt` are resolved via Aliyun DNS for optimal results in China 🇨🇳.
- **Fastest Upstream Selection**: Automatically picks the fastest responder among upstreams (e.g., 1.1.1.1:53, 8.8.8.8:53, or https://1.1.1.1) 🔒.
- **HTTPS over DNS Upstream Support**: Provides secure and private DNS resolution over HTTPS.
- **IPv4 Preference**: When both IPv4 and IPv6 records are available, only the IPv4 response is served to minimize leaks 🛡️.
- **Caching**: Built-in caching ensures rapid query responses ⚡.
- **JSON Storage**: When control-c is pressed, valid cache will be stored to `cache.json` and restored on next start.

## Installation 🔧

```bash
git clone https://github.com/c2h2/c2dns.git
cd c2dns
go build -o c2dns
```

## Usage 📖

```bash
./c2dns 
```