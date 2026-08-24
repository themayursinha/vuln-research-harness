// Package executor defines how planned requests are actually run. The v1
// implementation is a manual inbox executor: VRH writes out structured
// request envelopes, a human or external agent harness executes them under
// its own isolation, and results come back through the inbox. Nothing in
// this package executes target code or opens the network.
package executor

import (
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
	for _, sub := range []string{dir, filepath.Join(dir, "requests"), filepath.Join(dir, "results")} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			return nil, fmt.Errorf("create inbox: %w", err)
		}
	}
	return &Inbox{dir: dir}, nil
}

// Publish writes one request as a JSON envelope. It refuses to overwrite an
// existing envelope so replays cannot clobber evidence.
func (i *Inbox) Publish(request worker.Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	path := filepath.Join(i.dir, "requests", request.ID+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("request %s already published", request.ID)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check request: %w", err)
	}
	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	return nil
}

// CollectResults reads every result envelope in the inbox and validates the
// schema. Claims from the accompanying capability report are verified
// against the gate before any result is trusted.
func (i *Inbox) CollectResults(gate *capability.Gate) ([]worker.Result, error) {
	entries, err := os.ReadDir(filepath.Join(i.dir, "results"))
	if err != nil {
		return nil, fmt.Errorf("read results: %w", err)
	}
	var results []worker.Result
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
		results = append(results, envelope.Result)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no result envelopes found in %s", i.dir)
	}
	return results, nil
}
