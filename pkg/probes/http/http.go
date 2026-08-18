// Package http provides HTTP banner grabbing probe functionality.
// It extracts OS version information from HTTP Server headers.
package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/probes"
)

// Default HTTP ports
const (
	HTTPPort  = 80
	HTTPSPort = 443
)

// Common Server header patterns for OS detection
var (
	// Apache patterns: Apache/2.4.41 (Ubuntu), Apache/2.4.6 (CentOS)
	apachePattern = regexp.MustCompile(`Apache/[\d.]+ \(([^)]+)\)`)

	// nginx patterns: nginx/1.18.0 (Ubuntu)
	nginxPattern = regexp.MustCompile(`nginx/[\d.]+ \(([^)]+)\)`)

	// IIS patterns: Microsoft-IIS/10.0
	iisPattern = regexp.MustCompile(`Microsoft-IIS/([\d.]+)`)

	// PHP patterns: PHP/8.1.2-1ubuntu2.14
	phpPattern = regexp.MustCompile(`PHP/([\d.]+)(?:-[\d]+)?([a-z]+)?`)

	// OpenResty (nginx-based)
	openrestyPattern = regexp.MustCompile(`openresty/([\d.]+)`)

	// LiteSpeed
	litespeedPattern = regexp.MustCompile(`LiteSpeed`)

	// Caddy
	caddyPattern = regexp.MustCompile(`Caddy`)
)

// IIS version to Windows version mapping
var iisToWindows = map[string]string{
	"10.0": "Windows Server 2016/2019/2022 or Windows 10/11",
	"8.5":  "Windows Server 2012 R2 or Windows 8.1",
	"8.0":  "Windows Server 2012 or Windows 8",
	"7.5":  "Windows Server 2008 R2 or Windows 7",
	"7.0":  "Windows Server 2008 or Windows Vista",
	"6.0":  "Windows Server 2003",
	"5.1":  "Windows XP",
	"5.0":  "Windows 2000",
}

// Probe implements the probes.Probe interface using HTTP header grabbing.
type Probe struct {
	timeout time.Duration
	ports   []int
}

// New creates a new HTTP banner probe with default ports.
func New(timeout time.Duration) *Probe {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Probe{
		timeout: timeout,
		ports:   []int{HTTPPort, HTTPSPort},
	}
}

// NewWithPorts creates a new HTTP banner probe for specific ports.
func NewWithPorts(ports []int, timeout time.Duration) *Probe {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if len(ports) == 0 {
		ports = []int{HTTPPort, HTTPSPort}
	}
	return &Probe{
		timeout: timeout,
		ports:   ports,
	}
}

// Name returns the probe type identifier.
func (p *Probe) Name() string {
	return "http"
}

// Probe attempts to grab HTTP headers and extract OS information.
func (p *Probe) Probe(ctx context.Context, target string) (probes.ProbeResult, error) {
	result := probes.NewProbeResult()
	result.Protocol = "http"

	// Try each port
	for _, port := range p.ports {
		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return result, nil
		default:
		}

		serverHeader, powered, err := p.tryHTTPPort(ctx, target, port)
		if err != nil {
			continue
		}

		result.Success = true
		result.Port = port

		if serverHeader != "" {
			result.Details["http_server"] = serverHeader
		}
		if powered != "" {
			result.Details["x_powered_by"] = powered
		}

		// Parse the headers for OS detection
		osInfo := ParseHTTPHeaders(serverHeader, powered)
		if osInfo.Family != "" {
			result.Details["os_family"] = osInfo.Family
		}
		if osInfo.Version != "" {
			result.Details["os_version"] = osInfo.Version
		}
		if osInfo.Hint != "" {
			result.Details["os_hint"] = osInfo.Hint
		}
		if osInfo.WebServer != "" {
			result.Details["web_server"] = osInfo.WebServer
		}

		return result, nil
	}

	result.Success = false
	result.Error = "no HTTP ports responded"
	return result, nil
}

// tryHTTPPort attempts to connect to a specific port and grab headers
func (p *Probe) tryHTTPPort(ctx context.Context, target string, port int) (server, powered string, err error) {
	addr := fmt.Sprintf("%s:%d", target, port)

	var conn net.Conn
	dialer := net.Dialer{Timeout: p.timeout}

	// Use TLS for HTTPS ports
	if port == HTTPSPort || port == 8443 {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		}
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return "", "", err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	_ = conn.SetDeadline(time.Now().Add(p.timeout))

	// Send minimal HTTP HEAD request
	request := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	_, err = conn.Write([]byte(request))
	if err != nil {
		return "", "", err
	}

	// Read response headers
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}

		// Parse headers
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
		}
		if strings.HasPrefix(strings.ToLower(line), "x-powered-by:") {
			powered = strings.TrimSpace(line[13:])
		}
	}

	return server, powered, nil
}

// OSInfo contains parsed OS information from HTTP headers.
type OSInfo struct {
	Family    string // linux, windows, freebsd, etc.
	Version   string // Ubuntu 22.04, Windows Server 2019, etc.
	Hint      string // Additional hints
	WebServer string // Apache, nginx, IIS, etc.
}

// ParseHTTPHeaders extracts OS information from HTTP headers.
func ParseHTTPHeaders(server, powered string) OSInfo {
	info := OSInfo{}

	// Check for IIS (definitive Windows indicator)
	if iisPattern.MatchString(server) {
		matches := iisPattern.FindStringSubmatch(server)
		info.Family = "windows"
		info.WebServer = "IIS " + matches[1]
		if version, ok := iisToWindows[matches[1]]; ok {
			info.Version = version
			info.Hint = "Microsoft IIS " + matches[1]
		}
		return info
	}

	// Check for Apache with OS info
	if apachePattern.MatchString(server) {
		matches := apachePattern.FindStringSubmatch(server)
		osHint := strings.ToLower(matches[1])
		info.WebServer = "Apache"

		switch {
		case strings.Contains(osHint, "ubuntu"):
			info.Family = "linux"
			info.Version = "Ubuntu"
			info.Hint = matches[1]
		case strings.Contains(osHint, "debian"):
			info.Family = "linux"
			info.Version = "Debian"
			info.Hint = matches[1]
		case strings.Contains(osHint, "centos"):
			info.Family = "linux"
			info.Version = "CentOS"
			info.Hint = matches[1]
		case strings.Contains(osHint, "red hat"), strings.Contains(osHint, "rhel"):
			info.Family = "linux"
			info.Version = "RHEL"
			info.Hint = matches[1]
		case strings.Contains(osHint, "fedora"):
			info.Family = "linux"
			info.Version = "Fedora"
			info.Hint = matches[1]
		case strings.Contains(osHint, "freebsd"):
			info.Family = "freebsd"
			info.Version = "FreeBSD"
			info.Hint = matches[1]
		case strings.Contains(osHint, "win"), strings.Contains(osHint, "windows"):
			info.Family = "windows"
			info.Hint = matches[1]
		case strings.Contains(osHint, "unix"):
			info.Family = "linux"
			info.Hint = "Unix-like: " + matches[1]
		default:
			info.Hint = matches[1]
		}
		return info
	}

	// Check for nginx with OS info
	if nginxPattern.MatchString(server) {
		matches := nginxPattern.FindStringSubmatch(server)
		osHint := strings.ToLower(matches[1])
		info.WebServer = "nginx"

		switch {
		case strings.Contains(osHint, "ubuntu"):
			info.Family = "linux"
			info.Version = "Ubuntu"
			info.Hint = matches[1]
		case strings.Contains(osHint, "debian"):
			info.Family = "linux"
			info.Version = "Debian"
			info.Hint = matches[1]
		default:
			info.Hint = matches[1]
		}
		return info
	}

	// Check for PHP in X-Powered-By (indicates likely Linux)
	if phpPattern.MatchString(powered) {
		matches := phpPattern.FindStringSubmatch(powered)
		if len(matches) > 2 && matches[2] != "" {
			osHint := strings.ToLower(matches[2])
			if strings.Contains(osHint, "ubuntu") {
				info.Family = "linux"
				info.Version = "Ubuntu"
				info.Hint = "PHP " + matches[1]
			} else if strings.Contains(osHint, "debian") {
				info.Family = "linux"
				info.Version = "Debian"
				info.Hint = "PHP " + matches[1]
			}
		}
	}

	// Basic server identification
	serverLower := strings.ToLower(server)
	switch {
	case strings.Contains(serverLower, "apache"):
		info.WebServer = "Apache"
		info.Family = "linux" // Most likely
	case strings.Contains(serverLower, "nginx"):
		info.WebServer = "nginx"
		info.Family = "linux" // Most likely
	case openrestyPattern.MatchString(server):
		info.WebServer = "OpenResty"
		info.Family = "linux"
	case litespeedPattern.MatchString(server):
		info.WebServer = "LiteSpeed"
		info.Family = "linux"
	case caddyPattern.MatchString(server):
		info.WebServer = "Caddy"
		// Caddy is cross-platform
	case strings.Contains(serverLower, "cloudflare"):
		info.WebServer = "Cloudflare"
		// Can't determine OS behind CDN
	}

	return info
}
