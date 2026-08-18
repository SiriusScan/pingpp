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
- **Library-first design** - Use as CLI or import in your Go projects
- **Sirius integration** - Works with the Sirius vulnerability scanning platform

## Installation

```bash
go install github.com/SiriusScan/ping++/cmd/pingpp@latest
```

Or build from source:

```bash
git clone https://github.com/SiriusScan/ping++
cd ping++
go build -o pingpp ./cmd/pingpp
```

## Usage

### CLI

```bash
# Scan a single host (shows only alive hosts by default)
pingpp -t 192.168.1.100

# Scan a subnet
pingpp -t 192.168.1.0/24

# Verbose output - shows detection reasoning
pingpp -t 192.168.1.100 -v

# Show all hosts (including offline)
pingpp -t 192.168.1.0/24 -a

# Verbose + all hosts (full detail)
pingpp -t 192.168.1.0/24 -v -a

# Scan with specific probes
pingpp -t 192.168.1.0/24 -probes icmp,tcp

# Output to JSON
pingpp -t 192.168.1.0/24 -json -o results.json

# Scan from file
pingpp -l targets.txt

# Unprivileged mode (no ICMP)
pingpp -t 192.168.1.0/24 -no-icmp
```

### Library

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/SiriusScan/ping++/pkg/runner"
)

func main() {
    options := runner.DefaultOptions()
    options.Targets = []string{"192.168.1.0/24"}
    options.ProbeTypes = []string{"icmp", "tcp"}
    options.Timeout = 3 * time.Second

    options.OnResult = func(result *runner.Result) {
        fmt.Printf("%s [%s] OS:%s TTL:%d\n",
            result.IP,
            boolToStatus(result.IsAlive),
            result.OSFamily,
            result.TTL,
        )
    }

    r, _ := runner.NewRunner(options)
    defer r.Close()

    r.RunEnumeration(context.Background())
}

func boolToStatus(alive bool) string {
    if alive { return "up" }
    return "down"
}
```

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

## Options

```
INPUT:
   -t, -target       Target to scan (IP, CIDR, hostname)
   -l, -list         File containing list of targets

PROBES:
   -p, -probes       Probe types to use (icmp,tcp,ssh,http,smb,arp)
   -ports            TCP ports for probing (default: 22,80,443)
   -no-icmp          Disable ICMP probing

OUTPUT:
   -o, -output       Output file
   -json             Output in JSON format
   -v, -verbose      Verbose output with detection reasoning
   -a, -all          Show all hosts (including offline; default: only alive)
   -silent           Silent mode
   -debug            Debug mode

CONFIGURATION:
   -timeout          Timeout in seconds (default: 3)
   -retries          Number of retries (default: 2)
   -rate             Probes per second (default: 100)
   -threads          Concurrent threads (default: 50)
   -resolve          Resolve hostnames

OUTPUT:
   -o, -output       Output file
   -json             Output in JSON format
   -silent           Silent mode
   -debug            Debug mode
```

## Integration with Sirius

ping++ integrates with the [Sirius](https://github.com/SiriusScan) vulnerability scanning platform as the fingerprinting engine:

```go
import "github.com/SiriusScan/ping++/integration/appscanner"

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
ping++/
├── cmd/pingpp/          # CLI entry point
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

### Building

```bash
go build ./...
```

### Testing

```bash
go test ./...
```

### Running locally

There is no `cmd/pingpp` binary yet. Use the enumeration example:

```bash
# Hostname or URL — protocol-confirmed services only
go run ./examples/scan -t https://n8n.example.com/

# Registrable domain seed (apex + www)
go run ./examples/scan -seed example.com

# Faster 5-port profile, machine-readable report
go run ./examples/scan -profile quick -json -o report.json 10.0.0.5
```

ICMP discovery needs root and is skipped automatically when unprivileged. TCP connect-open is not treated as a service: the example reports protocol-confirmed endpoints separately from accept-all middleboxes.

## Dependencies

- [pro-bing](https://github.com/prometheus-community/pro-bing) - ICMP operations
- [goflags](https://github.com/projectdiscovery/goflags) - CLI parsing
- [gologger](https://github.com/projectdiscovery/gologger) - Logging
- [go-api](https://github.com/SiriusScan/go-api) - Sirius types

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [Sirius](https://github.com/SiriusScan/Sirius) - Vulnerability scanning platform
- [app-scanner](https://github.com/SiriusScan/app-scanner) - Port scanning and service detection
- [naabu](https://github.com/projectdiscovery/naabu) - Port scanner (inspiration)
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP toolkit (inspiration)
