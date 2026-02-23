// Example: Using ping++ as a library
//
// This example demonstrates how to use ping++ programmatically
// to scan a target and detect OS information.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/runner"
)

func main() {
	// Create options
	options := runner.DefaultOptions()
	options.Targets = []string{"127.0.0.1"} // Scan localhost
	options.ProbeTypes = []string{"icmp", "tcp"}
	options.Timeout = 3 * time.Second
	options.Threads = 10

	// Set up result callback
	options.OnResult = func(result *runner.Result) {
		fmt.Printf("Host: %s\n", result.IP)
		fmt.Printf("  Alive: %t\n", result.IsAlive)
		fmt.Printf("  OS Family: %s\n", result.OSFamily)
		fmt.Printf("  TTL: %d\n", result.TTL)
		fmt.Printf("  Latency: %s\n", result.Latency)
		fmt.Println()
	}

	// Create runner
	r, err := runner.NewRunner(options)
	if err != nil {
		fmt.Printf("Error creating runner: %v\n", err)
		return
	}
	defer r.Close()

	// Run enumeration
	ctx := context.Background()
	if err := r.RunEnumeration(ctx); err != nil {
		fmt.Printf("Error during scan: %v\n", err)
		return
	}

	// Print stats
	total, scanned, alive := r.Stats()
	fmt.Printf("Scan complete: %d/%d hosts, %d alive\n", scanned, total, alive)
}
