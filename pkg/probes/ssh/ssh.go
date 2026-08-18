// Package ssh provides SSH banner grabbing probe functionality.
// It extracts OS version information from SSH server banners.
package ssh

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/probes"
)

// SSHPort is the standard SSH port.
const SSHPort = 22

// Common SSH banner patterns for OS detection
var (
	// Ubuntu: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
	ubuntuPattern = regexp.MustCompile(`Ubuntu[_-]?(\d+(?:\.\d+)*)?`)

	// Debian: SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1
	debianPattern = regexp.MustCompile(`Debian[_-]?(\d+)?`)

	// FreeBSD: SSH-2.0-OpenSSH_8.0 FreeBSD-20211221
	freebsdPattern = regexp.MustCompile(`FreeBSD[_-]?(\d+(?:\.\d+)?)?`)

	// CentOS/RHEL: SSH-2.0-OpenSSH_7.4
	rhelPattern = regexp.MustCompile(`(?i)(rhel|centos|red\s*hat)[_-]?(\d+)?`)

	// Windows: SSH-2.0-OpenSSH_for_Windows_8.1
	windowsSSHPattern = regexp.MustCompile(`(?i)OpenSSH[_-]for[_-]Windows[_-]?(\d+(?:\.\d+)?)?`)

	// Cisco: SSH-2.0-Cisco-1.25
	ciscoPattern = regexp.MustCompile(`(?i)Cisco[_-]?(\d+(?:\.\d+)?)?`)

	// Dropbear (common on embedded/routers): SSH-2.0-dropbear_2020.81
	dropbearPattern = regexp.MustCompile(`(?i)dropbear[_-]?(\d+(?:\.\d+)?)?`)

	// OpenSSH version extraction
	opensshVersionPattern = regexp.MustCompile(`OpenSSH[_-](\d+\.\d+)`)
)

// OpenSSH version to potential OS mapping (approximate)
// These are rough estimates based on default OpenSSH versions in distros
var opensshVersionHints = map[string]string{
	"9.6": "Ubuntu 24.04 / Debian 13 / FreeBSD 14",
	"9.3": "Ubuntu 23.10 / Debian 12",
	"8.9": "Ubuntu 22.04",
	"8.4": "Debian 11 / Ubuntu 21.04",
	"8.2": "Ubuntu 20.04",
	"7.9": "Debian 10",
	"7.6": "Ubuntu 18.04",
	"7.4": "CentOS/RHEL 7",
	"6.7": "CentOS/RHEL 6",
}

// Probe implements the probes.Probe interface using SSH banner grabbing.
type Probe struct {
	timeout time.Duration
	port    int
}

// New creates a new SSH banner probe.
func New(timeout time.Duration) *Probe {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Probe{
		timeout: timeout,
		port:    SSHPort,
	}
}

// NewWithPort creates a new SSH banner probe for a specific port.
func NewWithPort(port int, timeout time.Duration) *Probe {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if port <= 0 {
		port = SSHPort
	}
	return &Probe{
		timeout: timeout,
		port:    port,
	}
}

// Name returns the probe type identifier.
func (p *Probe) Name() string {
	return "ssh"
}

// Probe attempts to grab the SSH banner and extract OS information.
func (p *Probe) Probe(ctx context.Context, target string) (probes.ProbeResult, error) {
	result := probes.NewProbeResult()
	result.Protocol = "ssh"
	result.Port = p.port

	addr := fmt.Sprintf("%s:%d", target, p.port)

	// Create dialer with timeout
	dialer := net.Dialer{Timeout: p.timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, nil
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(p.timeout))

	// Read the SSH banner (first line)
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		// Connection successful but couldn't read banner
		result.Success = true
		result.Error = "connected but no banner received"
		result.Details["ssh_port_open"] = "true"
		return result, nil
	}

	banner = strings.TrimSpace(banner)
	result.Success = true
	result.Details["ssh_banner"] = banner
	result.Details["ssh_port_open"] = "true"

	// Parse the banner for OS detection
	osInfo := ParseSSHBanner(banner)
	if osInfo.Family != "" {
		result.Details["os_family"] = osInfo.Family
	}
	if osInfo.Version != "" {
		result.Details["os_version"] = osInfo.Version
	}
	if osInfo.Hint != "" {
		result.Details["os_hint"] = osInfo.Hint
	}

	return result, nil
}

// OSInfo contains parsed OS information from an SSH banner.
type OSInfo struct {
	Family  string // linux, windows, freebsd, cisco, etc.
	Version string // Ubuntu 22.04, Windows 10, etc.
	Hint    string // Additional hints
	Raw     string // Raw banner
}

// ParseSSHBanner extracts OS information from an SSH banner.
func ParseSSHBanner(banner string) OSInfo {
	info := OSInfo{Raw: banner}

	// Check for Windows SSH
	if windowsSSHPattern.MatchString(banner) {
		info.Family = "windows"
		matches := windowsSSHPattern.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			info.Version = "Windows (OpenSSH " + matches[1] + ")"
			info.Hint = "OpenSSH for Windows " + matches[1]
		}
		return info
	}

	// Check for Cisco
	if ciscoPattern.MatchString(banner) {
		info.Family = "cisco"
		if matches := ciscoPattern.FindStringSubmatch(banner); len(matches) > 1 && matches[1] != "" {
			info.Version = "Cisco IOS"
			info.Hint = matches[1]
		}
		return info
	}

	// Check for Dropbear (embedded/routers)
	if dropbearPattern.MatchString(banner) {
		info.Family = "linux"
		info.Hint = "Embedded Linux (Dropbear)"
		if matches := dropbearPattern.FindStringSubmatch(banner); len(matches) > 1 && matches[1] != "" {
			info.Hint += " " + matches[1]
		}
		return info
	}

	// Check for Ubuntu
	if ubuntuPattern.MatchString(banner) {
		info.Family = "linux"
		if matches := ubuntuPattern.FindStringSubmatch(banner); len(matches) > 1 && matches[1] != "" {
			info.Version = "Ubuntu"
			info.Hint = parseUbuntuVersion(matches[1])
		} else {
			info.Version = "Ubuntu"
		}
		return info
	}

	// Check for Debian
	if debianPattern.MatchString(banner) {
		info.Family = "linux"
		info.Version = "Debian"
		if matches := debianPattern.FindStringSubmatch(banner); len(matches) > 1 && matches[1] != "" {
			info.Hint = "Debian " + matches[1]
		}
		return info
	}

	// Check for FreeBSD
	if freebsdPattern.MatchString(banner) {
		info.Family = "freebsd"
		info.Version = "FreeBSD"
		if matches := freebsdPattern.FindStringSubmatch(banner); len(matches) > 1 && matches[1] != "" {
			info.Hint = "FreeBSD " + matches[1]
		}
		return info
	}

	// Check for RHEL/CentOS
	if rhelPattern.MatchString(banner) {
		info.Family = "linux"
		if matches := rhelPattern.FindStringSubmatch(banner); len(matches) > 2 {
			info.Version = matches[1] // rhel or centos
			if matches[2] != "" {
				info.Hint = matches[1] + " " + matches[2]
			}
		}
		return info
	}

	// Fall back to OpenSSH version detection
	if opensshVersionPattern.MatchString(banner) {
		matches := opensshVersionPattern.FindStringSubmatch(banner)
		if len(matches) > 1 {
			version := matches[1]
			if hint, ok := opensshVersionHints[version]; ok {
				info.Hint = "OpenSSH " + version + " (likely " + hint + ")"
			} else {
				info.Hint = "OpenSSH " + version
			}
			// OpenSSH without OS indicator is usually Linux/Unix
			info.Family = "linux"
		}
	}

	return info
}

// parseUbuntuVersion converts Ubuntu package version to release name
func parseUbuntuVersion(pkgVersion string) string {
	// Ubuntu package versions like "3ubuntu0.1" indicate Ubuntu release
	// The prefix number loosely correlates with Ubuntu version
	// This is approximate - the SSH banner Ubuntu suffix encodes the package version
	if strings.HasPrefix(pkgVersion, "3") {
		return "Ubuntu 22.04+"
	}
	if strings.HasPrefix(pkgVersion, "2") {
		return "Ubuntu 20.04+"
	}
	if strings.HasPrefix(pkgVersion, "1") {
		return "Ubuntu 18.04+"
	}
	return "Ubuntu"
}
