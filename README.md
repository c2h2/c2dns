# c<sup>2</sup>dns

I am frustrated by the limitations of the DNS resolvers bundled with OpenWRT or dnsmasq.

So I write this c<sup>2</sup>dns.

c<sup>2</sup>dns is a lightspeed, lightweight DNS resolver in Go. 一个Go的轻量化、高速 DNS 解析器, 适合配合openwrt使用 🚀

- **Multi-Port Support**: Listens on TCP/UDP port 53 and HTTP port 8080, with upstream support for TCP, UDP, HTTP, and HTTPS.
- **China List Routing**: Domains specified in `chinalist.txt` are resolved via Aliyun DNS for optimal results in China 🇨🇳.
- **Fastest Upstream Selection**: Automatically picks the fastest responder among upstreams (e.g., 1.1.1.1:53, 8.8.8.8:53, or https://1.1.1.1) 🔒.
- **HTTPS over DNS Upstream Support**: Provides secure and private DNS resolution over HTTPS.
- **IPv4 Preference**: When both IPv4 and IPv6 records are available, only the IPv4 response is served to minimize leaks 🛡️.
- **Caching**: Built-in caching ensures rapid query responses ⚡.
- **JSON Storage**: On termination (Ctrl‑C), valid cache entries are saved to `cache_db.json` and reloaded on the next start, ensuring continuity.
- **Record Statistics**: c²dns keeps track of response record types (A, AAAA, MX, CNAME, etc.), giving you detailed insights into DNS activity.
- **Precompiled**: c2dns is precompiled for most architectures, soon to be added.

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