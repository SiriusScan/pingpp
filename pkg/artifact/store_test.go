package artifact

import (
	"bytes"
	"strings"
	"testing"
)

func TestMemoryStorePutGetContentAddress(t *testing.T) {
	s := NewMemoryStore(1024)
	art, err := s.Put("text/plain", []byte("hello"), "banner")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(art.ID, "sha256:") {
		t.Fatalf("id=%q", art.ID)
	}
	if art.Size != 5 {
		t.Fatalf("size=%d", art.Size)
	}
	data, got, err := s.Get(art.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("hello")) {
		t.Fatalf("data=%q", data)
	}
	if got.SHA256 != art.SHA256 {
		t.Fatal("sha mismatch")
	}
	// Same content → same ID
	art2, err := s.Put("text/plain", []byte("hello"), "again")
	if err != nil {
		t.Fatal(err)
	}
	if art2.ID != art.ID {
		t.Fatalf("content address unstable: %s vs %s", art.ID, art2.ID)
	}
}

func TestMemoryStoreRejectsOversize(t *testing.T) {
	s := NewMemoryStore(8)
	_, err := s.Put("application/octet-stream", make([]byte, 9), "too big")
	if err == nil {
		t.Fatal("expected size error")
	}
}
