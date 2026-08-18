package model

import (
	"encoding/json"
	"time"
)

// ObservationRecord is the immutable generic envelope for collector output.
// Protocol-specific data belongs in Payload as a typed JSON document —
// never as fields on Asset or this envelope.
type ObservationRecord struct {
	ID               string          `json:"id"`
	ProbeID          string          `json:"probe_id"`
	ObservationType  string          `json:"observation_type"`
	AssetID          string          `json:"asset_id"`
	Endpoint         *EndpointRef    `json:"endpoint,omitempty"`
	Timestamp        time.Time       `json:"timestamp"`
	CorrelationGroup string          `json:"correlation_group,omitempty"`
	ArtifactIDs      []string        `json:"artifact_ids,omitempty"`
	Payload          json.RawMessage `json:"payload,omitempty"`
	// Completeness describes how complete the observation is (optional).
	Completeness string `json:"completeness,omitempty"`
	// Error is a non-internal collector outcome message when applicable.
	Error string `json:"error,omitempty"`
}

// SetPayload marshals v into Payload.
func (o *ObservationRecord) SetPayload(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	o.Payload = data
	return nil
}

// DecodePayload unmarshals Payload into dest.
func (o *ObservationRecord) DecodePayload(dest any) error {
	if len(o.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(o.Payload, dest)
}

// Common observation type constants.
const (
	ObservationTCPEndpoint = "tcp.endpoint"
	ObservationICMPEcho    = "icmp.echo"
	ObservationTLS         = "tls"
	ObservationHTTP        = "http"
	ObservationSSH         = "ssh"
	ObservationSMB         = "smb"
	ObservationBanner      = "banner"
	ObservationUDPEndpoint = "udp.endpoint"
)

// TCPEndpointObservation is the typed payload for TCP endpoint enumeration.
type TCPEndpointObservation struct {
	State   EndpointState `json:"state"`
	Latency string        `json:"latency,omitempty"`
}

// ICMPObservation is the typed payload for ICMP echo responses.
type ICMPObservation struct {
	TTL     int    `json:"ttl,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// TLSObservation is the typed payload for TLS metadata collection.
type TLSObservation struct {
	Version      uint16                   `json:"version,omitempty"`
	CipherSuite  uint16                   `json:"cipher_suite,omitempty"`
	ALPN         string                   `json:"alpn,omitempty"`
	ServerName   string                   `json:"server_name,omitempty"`
	Certificates []CertificateObservation `json:"certificates,omitempty"`
}

// CertificateObservation holds parsed certificate identity fields.
type CertificateObservation struct {
	SubjectCN  string    `json:"subject_cn,omitempty"`
	IssuerCN   string    `json:"issuer_cn,omitempty"`
	SANs       []string  `json:"sans,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	SPKISHA256 string    `json:"spki_sha256,omitempty"`
}

// HTTPObservation is the typed payload for HTTP collection.
type HTTPObservation struct {
	URL              string              `json:"url,omitempty"`
	StatusCode       int                 `json:"status_code,omitempty"`
	Headers          map[string][]string `json:"headers,omitempty"`
	Title            string              `json:"title,omitempty"`
	MetaGenerator    string              `json:"meta_generator,omitempty"`
	CookieNames      []string            `json:"cookie_names,omitempty"`
	AuthSchemes      []string            `json:"auth_schemes,omitempty"`
	Server           string              `json:"server,omitempty"`
	PoweredBy        string              `json:"powered_by,omitempty"`
	Via              string              `json:"via,omitempty"`
	Location         string              `json:"location,omitempty"`
	CSP              string              `json:"csp,omitempty"`
	BodyLength       int64               `json:"body_length,omitempty"`
	Truncated        bool                `json:"truncated,omitempty"`
	EffectiveURL     string              `json:"effective_url,omitempty"`
	RawBodySHA256    string              `json:"raw_body_sha256,omitempty"`
	NormalizedSHA256 string              `json:"normalized_body_sha256,omitempty"`
	SimHash          uint64              `json:"simhash,omitempty"`
	Favicon          *FaviconObservation `json:"favicon,omitempty"`
	RedirectChain    []Redirect          `json:"redirect_chain,omitempty"`
	// Body is filled at fingerprint time from artifacts; collectors should not
	// put large bodies here.
	Body string `json:"body,omitempty"`
}

// FaviconObservation holds favicon hash material.
type FaviconObservation struct {
	SHA256 string `json:"sha256,omitempty"`
	MMH3   int32  `json:"mmh3,omitempty"`
	URL    string `json:"url,omitempty"`
}

// BannerObservation is generic first-bytes evidence. It is not a protocol identity.
type BannerObservation struct {
	Text      string `json:"text,omitempty"`
	Hex       string `json:"hex,omitempty"`
	Length    int    `json:"length,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// UDPEndpointObservation is the typed payload for UDP endpoint enumeration.
type UDPEndpointObservation struct {
	State   EndpointState `json:"state"`
	Latency string        `json:"latency,omitempty"`
}

// Redirect is one hop in an HTTP redirect chain.
type Redirect struct {
	StatusCode int    `json:"status_code,omitempty"`
	Location   string `json:"location,omitempty"`
	URL        string `json:"url,omitempty"`
}

// SSHObservation is the typed payload for SSH collection.
type SSHObservation struct {
	Banner               string   `json:"banner,omitempty"`
	ProtocolVersion      string   `json:"protocol_version,omitempty"`
	KexAlgorithms        []string `json:"kex_algorithms,omitempty"`
	HostKeyAlgorithms    []string `json:"host_key_algorithms,omitempty"`
	EncryptionAlgorithms []string `json:"encryption_algorithms,omitempty"`
	MACAlgorithms        []string `json:"mac_algorithms,omitempty"`
	Compression          []string `json:"compression,omitempty"`
}

// SMBObservation is the typed payload for SMB/NTLM collection.
type SMBObservation struct {
	Dialect       string `json:"dialect,omitempty"`
	Signing       string `json:"signing,omitempty"`
	OSBuild       string `json:"os_build,omitempty"`
	OSVersionHint string `json:"os_version_hint,omitempty"`
	ComputerName  string `json:"computer_name,omitempty"`
	Domain        string `json:"domain,omitempty"`
}
