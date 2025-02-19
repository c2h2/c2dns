# c2dns 🌐

c2dns is a lightweight, high-speed DNS resolver written in Go 🚀. c2dns 是一个用 Go 语言编写的轻量级、高速 DNS 解析器 🚀

- **Multi-Port Support**:  Listens on TCP/UDP port 53 and HTTP port 8080, with upstream support for TCP, UDP, HTTP, and HTTPS.
- **China List Routing**:  Domains specified in `chinalist.txt` are resolved via Aliyun DNS for optimal results in China 🇨🇳.
- **Fastest Upstream Selection**:  Automatically picks the fastest responder among upstreams (e.g., 1.1.1.1:53, 8.8.8.8:53, or 1.1.1.1 over HTTPS) 🔒.
- **HTTPS over DNS Upstream Support**:  Provides secure and private DNS resolution over HTTPS.
- **IPv4 Preference**:  When both IPv4 and IPv6 records are available, only the IPv4 response is served to minimize leaks 🛡️.
- **Caching**:  Built-in caching ensures rapid query responses ⚡.

- **多端口支持**：监听 TCP/UDP 53 端口和 HTTP 8080 端口，支持 TCP、UDP、HTTP 和 HTTPS 上游服务器。
- **中国域名路由**： `chinalist.txt` 中的域名将通过阿里云 DNS 解析，优化国内解析效果 🇨🇳。
- **最快上游选择**： 自动选择最快响应的上游（如 1.1.1.1:53、8.8.8.8:53 或 1.1.1.1 的 HTTPS）🔒。
- **HTTPS over DNS 上游支持**：提供安全、私密的 HTTPS DNS 解析服务。
- **优先返回 IPv4**：若同时存在 IPv4 和 IPv6 记录，仅返回 IPv4 响应，降低泄漏风险 🛡️.
- **缓存机制**：内置缓存确保快速响应 DNS 查询 ⚡.

## Installation 🔧

```bash
git clone https://github.com/yourusername/c2dns.git
cd c2dns
go build -o c2dns
```

## Usage 📖

```bash
./c2dns 
```