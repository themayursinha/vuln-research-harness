package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/themayursinha/vuln-research-harness/internal/coordinator"
	"github.com/themayursinha/vuln-research-harness/internal/executor"
	"github.com/themayursinha/vuln-research-harness/internal/ledger"
	"github.com/themayursinha/vuln-research-harness/internal/manifest"
	"github.com/themayursinha/vuln-research-harness/internal/registry"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
)

// roundState persists the coordinator round across CLI invocations.
type roundState struct {
	Round      int `json:"round"`
	MaxWorkers int `json:"max_workers"`
}

func campaignFiles(dir string) map[string]string {
	return map[string]string{
		"contract": filepath.Join(dir, "campaign.yaml"),
		"manifest": filepath.Join(dir, "manifest.json"),
		"registry": filepath.Join(dir, "registry.json"),
		"ledger":   filepath.Join(dir, "ledger.jsonl"),
		"state":    filepath.Join(dir, "state.json"),
		"inbox":    filepath.Join(dir, "inbox"),
	}
}

func snapshotCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("snapshot requires <source-dir> <campaign-dir>")
	}
	m, err := manifest.Snapshot(args[0], args[1])
	if err != nil {
		return err
	}
	fmt.Printf("snapshot complete: %d files, digest sha256:%s\n", m.FileCount, m.ArchiveSHA)
	fmt.Println("set target.source_snapshot in the campaign contract to that digest")
	return nil
}

func familiesCmd(args []string) error {
	if len(args) < 2 {
		return errors.New("families requires <add|block|reopen|list> <campaign-dir> [family] [mechanism-or-reason]")
	}
	sub, dir := args[0], args[1]
	reg, err := loadRegistry(dir)
	if err != nil {
		return err
	}
	switch sub {
	case "add":
		if len(args) != 4 {
			return errors.New("families add requires <campaign-dir> <family> <mechanism>")
		}
		if err := reg.Add(args[2], args[3]); err != nil {
			return err
		}
		return reg.Save(dir)
	case "block":
		if len(args) != 4 {
			return errors.New("families block requires <campaign-dir> <family> <reason>")
		}
		if err := reg.Block(args[2], args[3]); err != nil {
			return err
		}
		return reg.Save(dir)
	case "reopen":
		if len(args) != 4 {
			return errors.New("families reopen requires <campaign-dir> <family> <new-mechanism>")
		}
		if err := reg.Reopen(args[2], args[3]); err != nil {
			return err
		}
		return reg.Save(dir)
	case "list":
		for _, approach := range reg.All() {
			fmt.Printf("%-8s %-20s attempts=%d  %s\n", approach.Status, approach.Family, approach.Attempts, approach.Mechanism)
		}
		return nil
	default:
		return fmt.Errorf("unknown families subcommand %q", sub)
	}
}

func loadRegistry(dir string) (*registry.Registry, error) {
	if _, err := os.Stat(filepath.Join(dir, "registry.json")); err != nil {
		if os.IsNotExist(err) {
			return registry.New(), nil
		}
		return nil, err
	}
	return registry.Load(dir)
}

func roundPlanCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("round plan requires <campaign-dir> <max-workers>")
	}
	dir := args[0]
	files := campaignFiles(dir)

	var maxWorkers int
	if _, err := fmt.Sscanf(args[1], "%d", &maxWorkers); err != nil || maxWorkers < 1 {
		return fmt.Errorf("max-workers must be a positive integer")
	}
	state, err := loadRoundState(files["state"], maxWorkers)
	if err != nil {
		return err
	}
	coord, err := coordinator.NewState(maxWorkers)
	if err != nil {
		return err
	}
	coord.Round = state.Round

	reg, err := loadRegistry(dir)
	if err != nil {
		return err
	}
	if len(reg.All()) == 0 {
		return errors.New("no approach families registered; use: vrh families add")
	}
	plan, err := coord.Plan(reg)
	if err != nil {
		return err
	}

	inbox, err := executor.NewInbox(files["inbox"])
	if err != nil {
		return err
	}
	ldg, err := ledger.Open(files["ledger"])
	if err != nil {
		return err
	}
	defer ldg.Close()

	for _, family := range plan.Dispatched {
		request := worker.Request{
			ID:     fmt.Sprintf("%s--r%d", family, coord.Round),
			Round:  coord.Round,
			Family: family,
			Goal:   "investigate " + family + " for primitives matching the campaign success criterion",
		}
		if err := inbox.Publish(request); err != nil {
			return err
		}
		if _, err := ldg.Append(request.ID, "request_published", map[string]string{"round": fmt.Sprint(coord.Round), "family": family}); err != nil {
			return err
		}
	}
	if err := reg.Save(dir); err != nil {
		return err
	}
	state.Round = coord.Round + 1
	if err := saveRoundState(files["state"], state); err != nil {
		return err
	}
	fmt.Printf("round %d planned: dispatched %s", plan.Round, strings.Join(plan.Dispatched, ", "))
	if len(plan.Blocked) > 0 {
		fmt.Printf(" (blocked: %s)", strings.Join(plan.Blocked, ", "))
	}
	fmt.Println()
	fmt.Println("request envelopes written to inbox/requests/")
	return nil
}

func roundIngestCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("round ingest requires <campaign-dir>")
	}
	dir := args[0]
	files := campaignFiles(dir)

	inbox, err := executor.NewInbox(files["inbox"])
	if err != nil {
		return err
	}
	results, err := inbox.CollectResults(executor.DefaultGate())
	if err != nil {
		return err
	}

	reg, err := loadRegistry(dir)
	if err != nil {
		return err
	}
	coord, err := coordinator.NewState(1)
	if err != nil {
		return err
	}
	if err := coord.Ingest(reg, results); err != nil {
		return err
	}
	if err := reg.Save(dir); err != nil {
		return err
	}
	ldg, err := ledger.Open(files["ledger"])
	if err != nil {
		return err
	}
	defer ldg.Close()
	for _, result := range results {
		if _, err := ldg.Append(result.RequestID, "result_ingested", map[string]string{
			"status":   string(result.Status),
			"findings": fmt.Sprint(len(result.Findings)),
		}); err != nil {
			return err
		}
	}
	fmt.Printf("ingested %d results\n", len(results))
	return nil
}

func loadRoundState(path string, maxWorkers int) (roundState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return roundState{Round: 1, MaxWorkers: maxWorkers}, nil
		}
		return roundState{}, err
	}
	var state roundState
	if err := json.Unmarshal(data, &state); err != nil {
		return roundState{}, fmt.Errorf("parse state: %w", err)
	}
	if state.Round < 1 {
		state.Round = 1
	}
	return state, nil
}

func saveRoundState(path string, state roundState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
