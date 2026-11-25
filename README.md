# ping++

> Fast network enumeration and OS fingerprinting tool

[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

**ping++** is a fast, modular network enumeration and OS fingerprinting tool written in Go. It rapidly detects host liveliness and identifies operating systems through multi-source fingerprinting with weighted evidence aggregation.

Key features:

- **Fast enumeration** - Scan /24 subnets in seconds
- **Multi-source OS detection** - SSH banners, HTTP headers, SMB negotiation, TTL, and port analysis
- **Confidence scoring** - Weighted evidence aggregation with confidence percentages
- **Multiple probe types** - ICMP, TCP, SSH, HTTP, SMB, ARP
- **Library-first design** - Import the runner and integration packages in Go
- **Sirius integration** - Works with the Sirius vulnerability scanning platform

## Installation

ping++ uses Go 1.24 or later. In an existing Go module, set
`PINGPP_REVISION` to the full SHA of a published commit that declares the
canonical module path, then add the library:

```bash
go get github.com/SiriusScan/pingpp/pkg/runner@"$PINGPP_REVISION"
```

Go records the resolved version and checksums in `go.mod` and `go.sum`.
If migrating from `github.com/SiriusScan/ping++`, update imports to
`github.com/SiriusScan/pingpp`, remove the old filesystem replacement
and run `go mod tidy`.

## Usage

### Library

This program verifies that an application can import the runner and use its
default configuration.

```go
package main

import "github.com/SiriusScan/pingpp/pkg/runner"

func main() {
    _ = runner.DefaultOptions()
}
```

See [examples/simple](examples/simple) for a runner usage example.

## Probe Types

| Probe  | Description                       | Privileges | OS Info                                       |
| ------ | --------------------------------- | ---------- | --------------------------------------------- |
| `icmp` | ICMP Echo (ping) with TTL capture | Root/Admin | TTL-based OS family                           |
| `tcp`  | TCP connection to common ports    | None       | Port detection                                |
| `ssh`  | SSH banner grabbing on port 22    | None       | OS version from banner (Ubuntu, Debian, etc.) |
| `http` | HTTP Server header analysis       | None       | OS from Apache/nginx/IIS headers              |
| `smb`  | SMB2 negotiation for Windows      | None       | Windows version detection                     |
| `arp`  | ARP for local network enumeration | Root/Admin | MAC vendor                                    |

## OS Detection

ping++ uses a **multi-source fingerprinting engine** with weighted evidence aggregation:

### Evidence Sources and Weights

| Source      | Weight | Description                                                              |
| ----------- | ------ | ------------------------------------------------------------------------ |
| SSH Banner  | 0.95   | Highly reliable, often includes exact distro (e.g., "Ubuntu-3ubuntu0.1") |
| SMB         | 0.90   | Windows-specific, extracts version from dialect                          |
| HTTP Server | 0.80   | Server header analysis (Apache/nginx/IIS)                                |
| Port Combo  | 0.70   | Strong correlation from port combinations (135+445+3389 = Windows)       |
| Single Port | 0.50   | Individual OS-specific ports (e.g., 548 = macOS)                         |
| TTL         | 0.30   | Fallback, less reliable                                                  |

### Example Output

```
192.168.1.100 [UP]
  OS: linux (Debian)
  Confidence: 62%
  Evidence:
    - ssh_banner: linux (Debian) [weight: 0.95]
      Raw: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
    - ttl: linux [weight: 0.30]
      Raw: TTL 64 (original: 64)
  SSH Banner: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2

192.168.1.200 [UP]
  OS: windows
  Confidence: 64%
  Evidence:
    - smb: windows [weight: 0.90]
      Raw: SMB port 445
    - ports: windows [weight: 0.38]
      Raw: Port 445 (SMB)
```

### Port-Based Heuristics

| Port(s)        | Service        | OS Indicator        |
| -------------- | -------------- | ------------------- |
| 135, 445, 3389 | RPC+SMB+RDP    | Windows (very high) |
| 445            | SMB            | Windows (strong)    |
| 548            | AFP            | macOS               |
| 111, 2049      | Portmapper+NFS | Linux/Unix          |
| 22 + 548       | SSH+AFP        | macOS               |

### TTL Fallback

| Original TTL | OS Family              |
| ------------ | ---------------------- |
| 64           | Linux, macOS, BSD      |
| 128          | Windows                |
| 255          | Cisco, network devices |

## Integration with Sirius

ping++ integrates with the [Sirius](https://github.com/SiriusScan) vulnerability scanning platform as the fingerprinting engine:

```go
import "github.com/SiriusScan/pingpp/integration/appscanner"

// Create strategy for app-scanner
strategy := appscanner.NewStrategy()

// Use in scan pipeline
result, err := strategy.Fingerprint("192.168.1.100")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Alive: %t, OS: %s\n", result.IsAlive, result.OSFamily)
```

## Project Structure

```
pingpp/
├── pkg/
│   ├── runner/          # Core runner and options
│   └── probes/          # Probe implementations
│       ├── icmp/        # ICMP probe
│       ├── tcp/         # TCP probe
│       ├── ssh/         # SSH banner probe
│       ├── http/        # HTTP header probe
│       ├── smb/         # SMB2 probe
│       └── arp/         # ARP probe
├── fingerprint/         # OS detection logic
│   ├── ttl.go           # TTL-based detection
│   ├── ports.go         # Port-based heuristics
│   ├── evidence.go      # Evidence structure
│   └── aggregator.go    # Weighted aggregation engine
├── integration/         # External integrations
│   └── appscanner/      # Sirius app-scanner adapter
└── examples/            # Usage examples
```

## Development

### Requirements

- Go 1.24+
- Root/Admin for ICMP probing (optional)

### Building and testing

```bash
git clone https://github.com/SiriusScan/pingpp.git
cd pingpp
GOWORK=off go build ./...
GOWORK=off go test -race ./...
```

## Dependencies

- [pro-bing](https://github.com/prometheus-community/pro-bing) - ICMP operations
- [gologger](https://github.com/projectdiscovery/gologger) - Logging

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [Sirius](https://github.com/SiriusScan/Sirius) - Vulnerability scanning platform
- [app-scanner](https://github.com/SiriusScan/app-scanner) - Port scanning and service detection
- [naabu](https://github.com/projectdiscovery/naabu) - Port scanner (inspiration)
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP toolkit (inspiration)
