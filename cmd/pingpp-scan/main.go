// pingpp-scan emits bounded TCP connection observations, without identity claims.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 4097 {
		fmt.Fprintln(os.Stderr, "usage: pingpp-scan IP:port ... (maximum 4096)")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, target := range os.Args[1:] {
		host, port, err := net.SplitHostPort(target)
		if err != nil || net.ParseIP(host) == nil {
			fmt.Fprintln(os.Stderr, "target must be a literal IP:port")
			os.Exit(2)
		}
		n, err := net.LookupPort("tcp", port)
		if err != nil || n < 1 {
			fmt.Fprintln(os.Stderr, "invalid port")
			os.Exit(2)
		}
		state := "unknown"
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 250*time.Millisecond)
		if err == nil {
			state = "open"
			c.Close()
		}
		doc := map[string]any{"schema_version": "pingpp.scan/v1", "asset": map[string]any{"endpoints": []any{map[string]any{"address": host, "port": n, "transport": "tcp", "state": state, "execution": "attempted"}}}}
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
