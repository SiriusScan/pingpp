package main

import (
	"encoding/json"
	"net"
	"os/exec"
	"testing"
)

func TestEmitter(t *testing.T) {
	binary := t.TempDir() + "/emitter"
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("%s %v", out, err)
	}
	for _, args := range [][]string{nil, {"example.com:80"}, {"127.0.0.1:0"}, {"invalid"}} {
		if err := exec.Command(binary, args...).Run(); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	check := func(want string) {
		out, err := exec.Command(binary, address).Output()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Schema string `json:"schema_version"`
			Asset  struct {
				Endpoints []struct {
					State     string
					Execution string
					Product   string
				}
			}
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Schema != "pingpp.scan/v1" || len(doc.Asset.Endpoints) != 1 {
			t.Fatalf("%s", out)
		}
		e := doc.Asset.Endpoints[0]
		if e.State != want || e.Execution != "attempted" || e.Product != "" {
			t.Fatalf("%s", out)
		}
	}
	check("open")
	listener.Close()
	check("unknown")
}
