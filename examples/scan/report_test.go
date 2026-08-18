package main

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

func TestConfirmedServiceRequiresProtocol(t *testing.T) {
	ep := model.EndpointRef{Address: "1.2.3.4", Port: 22, Transport: model.TransportTCP}

	tcp := model.ObservationRecord{ObservationType: model.ObservationTCPEndpoint, Endpoint: &ep}
	_ = tcp.SetPayload(model.TCPEndpointObservation{State: model.EndpointOpen})
	if _, ok := confirmedService(tcp); ok {
		t.Fatal("tcp.endpoint must not count as a confirmed service")
	}

	emptyFTP := model.ObservationRecord{ObservationType: textproto.ObsFTP, Endpoint: &ep}
	_ = emptyFTP.SetPayload(textproto.BannerObservation{})
	if _, ok := confirmedService(emptyFTP); ok {
		t.Fatal("empty banner is not confirmation")
	}

	ssh := model.ObservationRecord{ObservationType: model.ObservationSSH, Endpoint: &ep}
	_ = ssh.SetPayload(model.SSHObservation{Banner: "SSH-2.0-OpenSSH_9.6"})
	hit, ok := confirmedService(ssh)
	if !ok || hit.Port != 22 || hit.Summary == "" {
		t.Fatalf("ssh hit=%+v ok=%v", hit, ok)
	}

	timedOut := model.ObservationRecord{
		ObservationType: model.ObservationHTTP,
		Endpoint:        &ep,
		Error:           "timeout",
	}
	if _, ok := confirmedService(timedOut); ok {
		t.Fatal("errored observation is not confirmation")
	}
}
