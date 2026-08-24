package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Save persists the registry to dir/registry.json.
func (r *Registry) Save(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}
	data, err := json.MarshalIndent(r.All(), "", "  ")
	if err != nil {
		return fmt.Errorf("encode registry: %w", err)
	}
	path := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write registry: %w", err)
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
