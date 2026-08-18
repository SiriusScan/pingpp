package engine

import (
	"context"
	"net"
	"testing"

	"github.com/SiriusScan/ping++/pkg/model"
)

func TestUniqueOrderedAddressesDedupsAndSorts(t *testing.T) {
	in := []model.Address{
		model.NewAddress("2001:db8::1"),
		model.NewAddress("192.0.2.10"),
		model.NewAddress("192.0.2.10"),
		model.NewAddress("::ffff:192.0.2.11"),
		model.NewAddress("2001:db8::1"),
	}
	got := uniqueOrderedAddresses(in)
	want := []string{"192.0.2.10", "192.0.2.11", "2001:db8::1"}
	if len(got) != len(want) {
		t.Fatalf("got=%v want=%v", ipsOf(got), want)
	}
	for i, ip := range want {
		if got[i].IP != ip {
			t.Fatalf("index %d ip=%s want %s (full=%v)", i, got[i].IP, ip, ipsOf(got))
		}
	}
	if got[0].Version != 4 || got[1].Version != 4 || got[2].Version != 6 {
		t.Fatalf("versions=%v", []int{got[0].Version, got[1].Version, got[2].Version})
	}
}

func TestResolveTargetOrdersAndDedupsLookup(t *testing.T) {
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("2001:db8::2")},
			{IP: net.ParseIP("192.0.2.20")},
			{IP: net.ParseIP("192.0.2.20")},
			{IP: net.ParseIP("::ffff:192.0.2.5")},
		}, nil
	}
	got, err := ResolveTarget(context.Background(), "multi.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "multi.example.test" {
		t.Fatalf("hostname=%q", got.Hostname)
	}
	want := []string{"192.0.2.5", "192.0.2.20", "2001:db8::2"}
	if len(got.Addresses) != len(want) {
		t.Fatalf("addresses=%v want %v", ipsOf(got.Addresses), want)
	}
	for i, ip := range want {
		if got.Addresses[i].IP != ip {
			t.Fatalf("index %d ip=%s want %s", i, got.Addresses[i].IP, ip)
		}
	}
}

func TestResolveTargetLiteralIP(t *testing.T) {
	got, err := ResolveTarget(context.Background(), "192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "" || len(got.Addresses) != 1 || got.Addresses[0].IP != "192.0.2.9" {
		t.Fatalf("literal IP target=%+v", got)
	}
}

func ipsOf(addrs []model.Address) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.IP
	}
	return out
}
