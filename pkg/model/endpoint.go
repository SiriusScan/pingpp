package model

// Transport is the transport-layer protocol for an endpoint.
type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// Valid reports whether t is a known transport.
func (t Transport) Valid() bool {
	switch t {
	case TransportTCP, TransportUDP:
		return true
	default:
		return false
	}
}

// EndpointState describes the observed state of an endpoint.
// Do not reduce this to a boolean Open.
//
// Open means a collector confirmed protocol behavior. A successful TCP
// connect without a protocol handshake is Responsive — accept-all
// middleboxes (NLBs, firewalls) SYN-ACK every port.
type EndpointState string

const (
	EndpointOpen       EndpointState = "open"
	EndpointClosed     EndpointState = "closed"
	EndpointFiltered   EndpointState = "filtered"
	EndpointResponsive EndpointState = "responsive"
	EndpointUnknown    EndpointState = "unknown"
)

// EndpointExecution is scan-plan completeness, independent of observed
// network state. A budget limit means we do not know because we did not ask.
type EndpointExecution string

const (
	ExecutionAttempted             EndpointExecution = "attempted"
	ExecutionNotAttemptedBudget    EndpointExecution = "not_attempted_budget"
	ExecutionNotAttemptedCancelled EndpointExecution = "not_attempted_cancelled"
	ExecutionTimedOut              EndpointExecution = "timed_out"
)

// Valid reports whether s is a known endpoint state.
func (s EndpointState) Valid() bool {
	switch s {
	case EndpointOpen, EndpointClosed, EndpointFiltered, EndpointResponsive, EndpointUnknown:
		return true
	default:
		return false
	}
}

// Endpoint is an address + transport + port with observed state.
type Endpoint struct {
	Address   string            `json:"address"`
	Port      uint16            `json:"port"`
	Transport Transport         `json:"transport"`
	State     EndpointState     `json:"state"`
	Execution EndpointExecution `json:"execution,omitempty"`
}

// Key returns a stable identifier for the endpoint.
func (e Endpoint) Key() string {
	return EndpointKey(e.Address, e.Port, e.Transport)
}

// Equal compares address, port, and transport (state ignored).
func (e Endpoint) Equal(other Endpoint) bool {
	return e.Address == other.Address && e.Port == other.Port && e.Transport == other.Transport
}

// EndpointRef is a lightweight reference used inside observations.
type EndpointRef struct {
	Address   string    `json:"address"`
	Port      uint16    `json:"port"`
	Transport Transport `json:"transport"`
}

// Ref returns an EndpointRef for e.
func (e Endpoint) Ref() EndpointRef {
	return EndpointRef{Address: e.Address, Port: e.Port, Transport: e.Transport}
}

// NewEndpoint constructs an endpoint with the given state.
func NewEndpoint(address string, port uint16, transport Transport, state EndpointState) Endpoint {
	if !transport.Valid() {
		transport = TransportTCP
	}
	if !state.Valid() {
		state = EndpointUnknown
	}
	return Endpoint{
		Address:   address,
		Port:      port,
		Transport: transport,
		State:     state,
	}
}
