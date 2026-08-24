// Package executor defines how planned requests are actually run. The v1
// implementation is a manual inbox executor: VRH writes out structured
// request envelopes, a human or external agent harness executes them under
// its own isolation, and results come back through the inbox. Nothing in
// this package executes target code or opens the network.
package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/themayursinha/vuln-research-harness/internal/capability"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
)

// DefaultGate is the capability set every executor must satisfy.
func DefaultGate() *capability.Gate {
	return capability.NewGate(
		"no_external_network",
		"no_real_credentials",
		"disposable_environment",
		"read_only_source_mount",
	)
}

// Inbox is a directory where planned requests are written and results are
// collected.
type Inbox struct {
	dir string
}

// NewInbox creates the inbox directory tree under dir.
func NewInbox(dir string) (*Inbox, error) {
	for _, sub := range []string{dir, filepath.Join(dir, "requests"), filepath.Join(dir, "results"), filepath.Join(dir, "results", "consumed")} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			return nil, fmt.Errorf("create inbox: %w", err)
		}
	}
	return &Inbox{dir: dir}, nil
}

// Publish writes one request as a JSON envelope. Publish is idempotent:
// re-publishing an identical envelope (after a crashed round plan) succeeds
// silently, while a conflicting envelope is refused.
func (i *Inbox) Publish(request worker.Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	path := filepath.Join(i.dir, "requests", request.ID+".json")
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, data) {
			return nil // already published, identical — retry-safe
		}
		return fmt.Errorf("request %s already published with different content", request.ID)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check request: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	return nil
}

// consumedRequestIDs returns every request ID whose envelope already sits in
// results/consumed/. Keys are read from the envelope content, not the
// filename, so a worker that names its file something other than
// <request_id>.json still marks the request consumed.
func (i *Inbox) consumedRequestIDs() (map[string]bool, error) {
	consumed := make(map[string]bool)
	entries, err := os.ReadDir(filepath.Join(i.dir, "results", "consumed"))
	if err != nil {
		return nil, fmt.Errorf("read consumed: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(i.dir, "results", "consumed", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var envelope struct {
			Result worker.Result `json:"result"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			continue // unreadable leftovers do not change outstanding state
		}
		if envelope.Result.RequestID != "" {
			consumed[envelope.Result.RequestID] = true
		}
	}
	return consumed, nil
}

// OutstandingRequests returns request IDs that have been published but not
// yet consumed by an ingest, mapped to their family. Consumed envelopes move
// to results/consumed/, so an old blocked result can never re-block a family
// after it was reopened.
func (i *Inbox) OutstandingRequests() (map[string]string, error) {
	consumed, err := i.consumedRequestIDs()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(i.dir, "requests"))
	if err != nil {
		return nil, fmt.Errorf("read requests: %w", err)
	}
	outstanding := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(i.dir, "requests", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var request worker.Request
		if err := json.Unmarshal(data, &request); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		if consumed[request.ID] {
			continue // already ingested
		}
		outstanding[request.ID] = request.Family
	}
	return outstanding, nil
}

// Collected is one accepted result envelope together with the file it came
// from, so consumption can act on the exact file that was read even when a
// worker names the envelope something other than <request_id>.json.
type Collected struct {
	Filename string
	Result   worker.Result
}

// CollectResults reads result envelopes, verifies the capability gate and
// schema, and accepts only results that answer an outstanding request. It
// returns the results together with their filenames so Consume can archive
// exactly the files that were read.
func (i *Inbox) CollectResults(gate *capability.Gate, outstanding map[string]string) ([]Collected, error) {
	if len(outstanding) == 0 {
		return nil, fmt.Errorf("no outstanding requests; nothing to collect")
	}
	entries, err := os.ReadDir(filepath.Join(i.dir, "results"))
	if err != nil {
		return nil, fmt.Errorf("read results: %w", err)
	}
	var collected []Collected
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(i.dir, "results", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var envelope struct {
			Capabilities []capability.Claim `json:"capabilities"`
			Result       worker.Result      `json:"result"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		report := gate.Verify(envelope.Capabilities)
		if !report.Passed {
			return nil, fmt.Errorf("capability gate failed for %s: %v", entry.Name(), report.Problems)
		}
		if err := envelope.Result.Validate(); err != nil {
			return nil, fmt.Errorf("invalid result in %s: %w", entry.Name(), err)
		}
		if _, ok := outstanding[envelope.Result.RequestID]; !ok {
			return nil, fmt.Errorf("result %q in %s does not answer an outstanding request", envelope.Result.RequestID, entry.Name())
		}
		for _, prior := range collected {
			if prior.Result.RequestID == envelope.Result.RequestID {
				return nil, fmt.Errorf("two result envelopes answer request %s (%s and %s); rejecting the batch", envelope.Result.RequestID, prior.Filename, entry.Name())
			}
		}
		collected = append(collected, Collected{Filename: entry.Name(), Result: envelope.Result})
	}
	if len(collected) == 0 {
		return nil, fmt.Errorf("no result envelopes found in %s", i.dir)
	}
	return collected, nil
}

// Consume marks collected envelopes as ingested by moving the exact files
// that were read to results/consumed/. Consumed request IDs are excluded
// from OutstandingRequests, so a stale blocked result can never re-block a
// family after it was reopened.
func (i *Inbox) Consume(collected []Collected) error {
	for _, item := range collected {
		src := filepath.Join(i.dir, "results", item.Filename)
		dst := filepath.Join(i.dir, "results", "consumed", item.Filename)
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat %s: %w", item.Filename, err)
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("consume %s: %w", item.Filename, err)
		}
	}
	return nil
}
