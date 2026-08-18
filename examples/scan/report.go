package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

// ScanDocument is the full library result for a single target.
// Downstream tools should consume this object, not a summarized view.
type ScanDocument struct {
	Target  string       `json:"target"`
	Profile string       `json:"profile"`
	Elapsed string       `json:"elapsed"`
	State   StateDump    `json:"state"`
	Asset   *model.Asset `json:"asset"`
}

// StateDump is ScanState without the mutex.
type StateDump struct {
	AssetID      string             `json:"asset_id"`
	Reachability model.Reachability `json:"reachability"`
	ProbesUsed   int                `json:"probes_used"`
	MaxProbes    int                `json:"max_probes"`
	Completed    []string           `json:"completed"`
}

func buildDocument(input string, profile engine.ProfileName, res *engine.ScanResult, elapsed time.Duration) ScanDocument {
	completed := make([]string, 0, len(res.State.Completed))
	for id, ok := range res.State.Completed {
		if ok {
			completed = append(completed, id)
		}
	}
	sort.Strings(completed)
	return ScanDocument{
		Target:  input,
		Profile: string(profile),
		Elapsed: elapsed.Round(time.Millisecond).String(),
		State: StateDump{
			AssetID:      res.State.AssetID,
			Reachability: res.State.Reachability,
			ProbesUsed:   res.State.Budget.ProbesUsed,
			MaxProbes:    res.State.Budget.MaxProbesPerHost,
			Completed:    completed,
		},
		Asset: res.Asset,
	}
}

func writeJSON(w io.Writer, docs []ScanDocument) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	payload := any(docs[0])
	if len(docs) > 1 {
		payload = docs
	}
	return enc.Encode(payload)
}

func writeText(w io.Writer, docs []ScanDocument) error {
	for i, doc := range docs {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, doc.Text()); err != nil {
			return err
		}
	}
	return nil
}

func (d ScanDocument) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "target        %s\n", d.Target)
	fmt.Fprintf(&b, "profile       %s\n", d.Profile)
	fmt.Fprintf(&b, "elapsed       %s\n", d.Elapsed)
	fmt.Fprintf(&b, "asset_id      %s\n", d.State.AssetID)
	fmt.Fprintf(&b, "reachability  %s (%s)\n", d.State.Reachability.State, strings.Join(d.State.Reachability.Reasons, ", "))
	fmt.Fprintf(&b, "probes        %d / %d\n", d.State.ProbesUsed, d.State.MaxProbes)
	if d.Asset != nil {
		fmt.Fprintf(&b, "hostnames     %s\n", strings.Join(d.Asset.Hostnames, ", "))
		ips := make([]string, 0, len(d.Asset.Addresses))
		for _, a := range d.Asset.Addresses {
			ips = append(ips, a.IP)
		}
		fmt.Fprintf(&b, "addresses     %s\n", strings.Join(ips, ", "))
	}
	fmt.Fprintf(&b, "completed     %s\n", strings.Join(d.State.Completed, ", "))

	if d.Asset == nil {
		return b.String()
	}

	fmt.Fprintf(&b, "\nendpoints (%d)\n", len(d.Asset.Endpoints))
	for _, ep := range d.Asset.Endpoints {
		fmt.Fprintf(&b, "  %s/%-5d %-12s %s\n", ep.Transport, ep.Port, ep.State, ep.Address)
	}

	fmt.Fprintf(&b, "\nclaims (%d)\n", len(d.Asset.Claims))
	for _, c := range d.Asset.Claims {
		raw, _ := json.MarshalIndent(c, "    ", "  ")
		fmt.Fprintf(&b, "  %s\n%s\n", c.ID, raw)
	}

	fmt.Fprintf(&b, "\nobservations (%d)\n", len(d.Asset.Observations))
	for _, o := range d.Asset.Observations {
		port := 0
		addr := ""
		if o.Endpoint != nil {
			port = int(o.Endpoint.Port)
			addr = o.Endpoint.Address
		}
		fmt.Fprintf(&b, "  %s  probe=%s  port=%d  addr=%s  completeness=%s\n", o.ObservationType, o.ProbeID, port, addr, o.Completeness)
		if o.Error != "" {
			fmt.Fprintf(&b, "    error: %s\n", o.Error)
		}
		if o.ID != "" {
			fmt.Fprintf(&b, "    id: %s\n", o.ID)
		}
		if o.CorrelationGroup != "" {
			fmt.Fprintf(&b, "    correlation: %s\n", o.CorrelationGroup)
		}
		if len(o.Payload) > 0 {
			var pretty any
			if json.Unmarshal(o.Payload, &pretty) == nil {
				raw, _ := json.MarshalIndent(pretty, "    ", "  ")
				fmt.Fprintf(&b, "    payload:\n    %s\n", raw)
			} else {
				fmt.Fprintf(&b, "    payload: %s\n", o.Payload)
			}
		}
	}
	return b.String()
}
