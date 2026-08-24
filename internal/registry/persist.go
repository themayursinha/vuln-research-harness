package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateFamilyName rejects family names that cannot be used as safe path
// components. Request IDs are derived as "<family>--r<round>" and become
// envelope filenames under inbox/requests/, so a family containing path
// separators or traversal segments would write envelopes outside the requests
// directory. Call it wherever untrusted family names enter the system.
func ValidateFamilyName(family string) error {
	if strings.TrimSpace(family) == "" || strings.ContainsAny(family, "/\\") ||
		family == "." || family == ".." {
		return fmt.Errorf("family %q must be a safe path component", family)
	}
	for _, segment := range strings.Split(family, "--") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("family %q must not contain empty, '.', or '..' segments split on '--'", family)
		}
	}
	if strings.TrimSpace(family) != family {
		return fmt.Errorf("family %q must not have leading or trailing whitespace", family)
	}
	return nil
}

// Save persists the registry to dir/registry.json atomically: a temporary file
// is written in full and then renamed over the target, so a crash can never
// leave a truncated registry.json behind that would block ledger-based
// reconciliation on the next command.
func (r *Registry) Save(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}
	for _, approach := range r.All() {
		if err := ValidateFamilyName(approach.Family); err != nil {
			return fmt.Errorf("refusing to persist unsafe registry entry: %w", err)
		}
	}
	data, err := json.MarshalIndent(r.All(), "", "  ")
	if err != nil {
		return fmt.Errorf("encode registry: %w", err)
	}
	path := filepath.Join(dir, "registry.json")
	tmp := filepath.Join(dir, ".registry.json.tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write registry temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace registry: %w", err)
	}
	return nil
}

// Load restores a registry previously written by Save.
func Load(dir string) (*Registry, error) {
	data, err := os.ReadFile(filepath.Join(dir, "registry.json"))
	if err != nil {
		return nil, fmt.Errorf("read registry: %w", err)
	}
	var approaches []Approach
	if err := json.Unmarshal(data, &approaches); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	registry := New()
	for _, approach := range approaches {
		if _, exists := registry.approaches[approach.Family]; exists {
			return nil, fmt.Errorf("duplicate family %q in saved registry", approach.Family)
		}
		registry.approaches[approach.Family] = approach
	}
	return registry, nil
}

// RecordDispatch increments the attempt counter for a family. Use it when the
// coordinator assigns work to a family so convergence accounting stays honest.
func (r *Registry) RecordDispatch(family string) error {
	approach, ok := r.approaches[family]
	if !ok {
		return fmt.Errorf("unknown approach family %q", family)
	}
	if approach.Status != Active {
		return fmt.Errorf("family %q is %s; only active families may receive work", family, approach.Status)
	}
	approach.Attempts++
	r.approaches[family] = approach
	return nil
}
