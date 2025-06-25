![RPDNS](https://raw.github.com/jedisct1/rpdns/master/rpdns.png)

# RPDNS - Caching Reverse DNS Proxy

[![Go Version](https://img.shields.io/badge/go-%3E%3D%201.21-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-ISC-green.svg)](LICENSE)

RPDNS is a high-performance caching reverse DNS proxy designed to reduce load on authoritative DNS servers and protect against denial-of-service attacks.

## Overview

```
[Clients] → [RPDNS] → [Authoritative Servers]
```

RPDNS sits between DNS clients and authoritative servers, providing:
- **Intelligent caching** to reduce upstream queries
- **DoS protection** through rate limiting and request validation
- **High availability** with automatic failover
- **Consistent performance** under load

While RPDNS can forward queries to recursive servers, it does not perform recursion itself. It's optimized for scenarios where you need to protect and accelerate access to authoritative DNS servers.

## Key Features

### 🛡️ Security & Protection
- **Response rate limiting** - Protects upstream servers from resource exhaustion
- **Query validation** - Blocks invalid and non-fully qualified queries
- **`ANY` query handling** - Responds with synthesized `HINFO` records per RFC 8482
- **DNSSEC support** - Full support for DNSSEC validation

### 🚀 Performance
- **ARC-based caching** - Adaptive replacement cache for optimal hit rates
- **EDNS0 support** - Handles large DNS payloads efficiently
- **Concurrent processing** - Handles thousands of simultaneous queries
- **Memory management** - Configurable memory limits with automatic cleanup

### 🔄 Reliability
- **Automatic failover** - Detects and routes around failed servers
- **Load balancing** - Consistent hashing for even distribution
- **Health monitoring** - Continuous upstream server health checks
- **TCP and UDP support** - Automatic TCP fallback for truncated responses

## Installation

### Prerequisites
- Go 1.21 or later
- Linux, macOS, or Windows

### From Source

```bash
# Clone the repository
git clone https://github.com/jedisct1/rpdns.git
cd rpdns

# Build the binary
go build -o rpdns .

# Or install directly
go install github.com/jedisct1/rpdns@latest
```

## Usage

### Quick Start

```bash
# Basic usage with custom upstream servers
sudo rpdns -upstream 1.1.1.1:53,8.8.8.8:53

# Production setup with tuning
sudo rpdns \
  -upstream 10.0.0.1:53,10.0.0.2:53 \
  -listen :53 \
  -maxclients 5000 \
  -cachesize 2097152 \
  -memsize 4096
```

### System Requirements

⚠️ **Important**: Ensure your system's file descriptor limit is set to at least `maxclients * 2`:

```bash
# Check current limit
ulimit -n

# Increase limit (temporary)
ulimit -n 10000

# For permanent changes, edit /etc/security/limits.conf
```

### Command Line Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-upstream` | string | `8.8.8.8:53,8.8.4.4:53` | Comma-delimited list of upstream DNS servers |
| `-listen` | string | `:53` | Address to listen on (TCP and UDP) |
| `-cachesize` | int | `1048576` | Number of DNS responses to cache |
| `-memsize` | uint | `2048` | Maximum memory usage in MB |
| `-maxclients` | uint | `1000` | Maximum simultaneous client connections |
| `-maxfailures` | uint | `100` | Failed queries before marking server offline |
| `-maxrtt` | float | `0.25` | Maximum mean RTT (seconds) before marking server dead |
| `-minlabels` | int | `2` | Minimum domain labels required |
| `-local-rrs` | string | | Path to local DNS records file |
| `-debug` | bool | `false` | Enable debug logging |

## Configuration

### Local DNS Records

RPDNS can serve local DNS records without forwarding to upstream servers. This is useful for:
- Internal service discovery
- Split-horizon DNS
- Development environments

Create a local records file:

```bash
# /etc/rpdns/local.zone
# Format: <name> <ttl> IN <type> <value>

# A records
app.internal.example.com.     86400 IN A     10.0.1.100
db.internal.example.com.      86400 IN A     10.0.1.101

# CNAME records
www.internal.example.com.     86400 IN CNAME app.internal.example.com.

# MX records
internal.example.com.         86400 IN MX    10 mail.internal.example.com.
```

Then start RPDNS with:

```bash
rpdns -local-rrs /etc/rpdns/local.zone
```

## Performance Tuning

### Cache Sizing

The cache size should be based on your query patterns:

```bash
# For small deployments (< 1000 queries/sec)
-cachesize 524288    # 512K entries
-memsize 1024        # 1GB RAM

# For medium deployments (1000-10000 queries/sec)
-cachesize 2097152   # 2M entries
-memsize 4096        # 4GB RAM

# For large deployments (> 10000 queries/sec)
-cachesize 8388608   # 8M entries
-memsize 16384       # 16GB RAM
```

### Upstream Server Selection

- Use geographically close servers to minimize RTT
- Configure multiple servers for redundancy
- Monitor server health with `-maxrtt` setting

## Deployment Examples

### Systemd Service

Create `/etc/systemd/system/rpdns.service`:

```ini
[Unit]
Description=RPDNS Caching DNS Proxy
After=network.target

[Service]
Type=simple
User=rpdns
Group=rpdns
ExecStart=/usr/local/bin/rpdns \
    -upstream 10.0.0.1:53,10.0.0.2:53 \
    -listen :53 \
    -maxclients 5000 \
    -cachesize 2097152 \
    -memsize 4096
Restart=always
RestartSec=5
LimitNOFILE=20000

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable rpdns
sudo systemctl start rpdns
```

### Docker Container

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o rpdns .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/rpdns /usr/local/bin/
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["rpdns"]
```

Run with:

```bash
docker run -d \
  --name rpdns \
  -p 53:53/tcp \
  -p 53:53/udp \
  rpdns:latest \
  -upstream 1.1.1.1:53,8.8.8.8:53
```

## Monitoring

RPDNS logs important events:

- Upstream server health changes
- Cache performance metrics (when in debug mode)
- Query failures and errors

Example log output:

```
2024/01/15 10:23:45 Configured upstream servers: [10.0.0.1:53 10.0.0.2:53]
2024/01/15 10:23:45 Probing [10.0.0.1:53] ... working, rtt=2.145ms
2024/01/15 10:23:45 Probing [10.0.0.2:53] ... working, rtt=1.832ms
2024/01/15 10:23:45 Live upstream servers: [10.0.0.1:53 10.0.0.2:53]
Ready
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

RPDNS is released under the ISC License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [miekg/dns](https://github.com/miekg/dns) - DNS library in Go
- Uses [hashicorp/golang-lru](https://github.com/hashicorp/golang-lru) for ARC caching
- [dchest/siphash](https://github.com/dchest/siphash) for consistent hashing
