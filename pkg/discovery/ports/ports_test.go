package ports

import "testing"

func TestPortListsNonEmpty(t *testing.T) {
	if len(TCPDefault()) < 60 {
		t.Fatalf("TCPDefault=%d", len(TCPDefault()))
	}
	if len(TCPQuick()) < 3 {
		t.Fatalf("TCPQuick=%d", len(TCPQuick()))
	}
	if len(UDPDefault()) < 5 {
		t.Fatalf("UDPDefault=%d", len(UDPDefault()))
	}
}
