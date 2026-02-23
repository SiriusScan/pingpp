// Package smb provides SMB-based probe functionality for Windows OS detection.
// It extracts OS version information from NTLMSSP challenge during SMB2/3 negotiation.
package smb

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/probes"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// SMBPort is the standard SMB port.
const SMBPort = 445

// Probe implements the probes.Probe interface using SMB connections.
type Probe struct {
	timeout time.Duration
}

// New creates a new SMB probe.
func New(timeout time.Duration) *Probe {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Probe{
		timeout: timeout,
	}
}

// Name returns the probe type identifier.
func (p *Probe) Name() string {
	return "smb"
}

// Probe attempts to connect to SMB and extract OS information via NTLMSSP.
// This performs SMB2/3 negotiation and extracts the Windows build number
// and version from the NTLMSSP challenge response.
func (p *Probe) Probe(ctx context.Context, target string) (probes.ProbeResult, error) {
	result := probes.NewProbeResult()
	result.Protocol = "smb"
	result.Port = SMBPort

	// Use null/anonymous session - no credentials needed for fingerprinting
	// The NTLMSSP challenge is sent before authentication completes
	options := gosmb.Options{
		Host:        target,
		Port:        SMBPort,
		DialTimeout: p.timeout,
		Initiator: &spnego.NTLMInitiator{
			User:     "",
			Password: "",
			Domain:   "",
		},
	}

	// NewConnection performs:
	// 1. TCP connection
	// 2. SMB2 Negotiate
	// 3. SessionSetup with NTLMSSP (extracts OS info from challenge)
	session, err := gosmb.NewConnection(options)
	if err != nil {
		// Connection or negotiation failed
		// Check if we got partial info from the error
		errStr := err.Error()

		// Some errors still indicate SMB is running and we may have target info
		// The NTLMSSP challenge is received before auth completes, so we can
		// still extract OS info even on auth failures
		if strings.Contains(errStr, "STATUS_ACCESS_DENIED") ||
			strings.Contains(errStr, "STATUS_LOGON_FAILURE") ||
			strings.Contains(errStr, "Logon failed") ||
			strings.Contains(errStr, "anonymous account doesn't support signing") ||
			strings.Contains(errStr, "guest account doesn't support signing") {
			// SMB is up but auth failed (expected for null session on some configs)
			result.Success = true
			result.Details["smb_port_open"] = "true"
			result.Details["smb_error"] = errStr

			// Try to extract info if session was partially established
			if session != nil {
				p.extractTargetInfo(session, &result)
				session.Close()
			}
			return result, nil
		}

		// Complete failure - SMB not available
		result.Success = false
		result.Error = errStr
		return result, nil
	}
	defer session.Close()

	// SMB connection successful
	result.Success = true
	result.Details["smb_port_open"] = "true"

	// Extract OS information from NTLMSSP challenge
	p.extractTargetInfo(session, &result)

	// Get signing status
	if session.IsSigningRequired() {
		result.Details["smb_signing"] = "required"
	} else {
		result.Details["smb_signing"] = "not_required"
	}

	return result, nil
}

// extractTargetInfo extracts OS and computer information from the SMB session
func (p *Probe) extractTargetInfo(session *gosmb.Connection, result *probes.ProbeResult) {
	targetInfo := session.GetTargetInfo()
	if targetInfo == nil {
		// No NTLMSSP target info available - likely Samba or non-Windows
		result.Details["os_family"] = "unknown"
		result.Details["os_hint"] = "SMB server (no NTLMSSP info)"
		return
	}

	// Extract version from raw OS field (uint64 containing version bytes)
	// Format: [ProductMajorVersion (1)][ProductMinorVersion (1)][ProductBuild (2)][Reserved (3)][Revision (1)]
	osBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(osBytes, targetInfo.OS)

	majorVersion := osBytes[0]
	minorVersion := osBytes[1]
	buildNumber := binary.LittleEndian.Uint16(osBytes[2:4])

	// Determine OS family
	if buildNumber > 0 && majorVersion > 0 {
		// Windows detected
		result.Details["os_family"] = "windows"

		// Get friendly version name from build number
		friendlyName := GetWindowsVersion(buildNumber)
		if friendlyName != "" {
			result.Details["os_version"] = friendlyName
		}

		// Store the raw version string
		result.Details["os_build"] = fmt.Sprintf("%d.%d.%d", majorVersion, minorVersion, buildNumber)

		// Use library's guessed version as fallback/confirmation
		if targetInfo.GuessedOSVersion != "" {
			result.Details["os_hint"] = targetInfo.GuessedOSVersion
		}
	} else if targetInfo.GuessedOSVersion != "" {
		// Fallback to library's guessed version
		if strings.Contains(strings.ToLower(targetInfo.GuessedOSVersion), "windows") {
			result.Details["os_family"] = "windows"
		} else {
			result.Details["os_family"] = "unknown"
		}
		result.Details["os_hint"] = targetInfo.GuessedOSVersion
	} else {
		// No version info - likely Samba
		result.Details["os_family"] = "linux"
		result.Details["os_hint"] = "Samba (SMB server without Windows version info)"
	}

	// Store computer and domain names
	if targetInfo.NBComputerName != "" {
		result.Details["computer_name"] = targetInfo.NBComputerName
	}
	if targetInfo.NBDomainName != "" {
		result.Details["domain"] = targetInfo.NBDomainName
	}
	if targetInfo.DnsComputerName != "" {
		result.Details["dns_computer_name"] = targetInfo.DnsComputerName
	}
	if targetInfo.DnsDomainName != "" {
		result.Details["dns_domain_name"] = targetInfo.DnsDomainName
	}
}
