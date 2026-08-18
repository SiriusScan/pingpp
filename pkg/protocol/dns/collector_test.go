package dns_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	dncol "github.com/SiriusScan/ping++/pkg/protocol/dns"
)

func TestDNSCollectorSpeaksDNSNotOSResolver(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Ns = append(m.Ns, &dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "a.root-servers.net."})
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	c, err := dncol.New(engine.Config{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportUDP, model.EndpointResponsive)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var p dncol.Observation
	if err := res.Observations[0].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if !p.Responded || len(p.Answers) == 0 {
		t.Fatalf("payload=%+v", p)
	}
}

func TestDNSCollectorNoMatchOnGarbage(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr) // echo is not a DNS message
	}()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	c, _ := dncol.New(engine.Config{Timeout: 300 * time.Millisecond})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportUDP, model.EndpointResponsive)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome == engine.OutcomeSuccess {
		t.Fatal("echoed garbage must not be a DNS match")
	}
}
