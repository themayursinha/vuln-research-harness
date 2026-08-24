package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/themayursinha/vuln-research-harness/internal/contract"
	"github.com/themayursinha/vuln-research-harness/internal/coordinator"
	"github.com/themayursinha/vuln-research-harness/internal/executor"
	"github.com/themayursinha/vuln-research-harness/internal/ledger"
	"github.com/themayursinha/vuln-research-harness/internal/manifest"
	"github.com/themayursinha/vuln-research-harness/internal/registry"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
)

// roundState persists the coordinator round across CLI invocations. The
// pending plan is recorded durably BEFORE any envelope is published so a
// crash mid-round can be retried with the exact original family set.
type roundState struct {
	Round        int      `json:"round"`
	MaxWorkers   int      `json:"max_workers"`
	PendingRound int      `json:"pending_round,omitempty"`
	PendingPlan  []string `json:"pending_plan,omitempty"`
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
		if err := appendFamilyEvent(dir, "family:"+args[2], "family_added", args[2], map[string]string{"mechanism": args[3]}); err != nil {
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
		if err := appendFamilyEvent(dir, "family:"+args[2], "family_blocked", args[2], map[string]string{"reason": args[3]}); err != nil {
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
		if err := appendFamilyEvent(dir, "family:"+args[2], "family_reopened", args[2], map[string]string{"mechanism": args[3]}); err != nil {
			return err
		}
		return reg.Save(dir)
	case "list":
		if err := reconcileForList(dir, reg); err != nil {
			return err
		}
		for _, approach := range reg.All() {
			fmt.Printf("%-8s %-20s attempts=%d  %s\n", approach.Status, approach.Family, approach.Attempts, approach.Mechanism)
		}
		return nil
	default:
		return fmt.Errorf("unknown families subcommand %q", sub)
	}
}

func appendFamilyEvent(dir, id, eventType, family string, data map[string]string) error {
	files := campaignFiles(dir)
	ldg, err := ledger.Open(files["ledger"])
	if err != nil {
		return err
	}
	defer ldg.Close()
	if data == nil {
		data = map[string]string{}
	}
	data["family"] = family
	_, err = ldg.Append(id, eventType, data)
	return err
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

// reconcileForList rebuilds the in-memory registry from the ledger so a list
// view is never stale, even if registry.json was lost or a prior command
// appended events after its last save. It persists the rebuilt view so the
// on-disk file matches the ledger again.
func reconcileForList(dir string, reg *registry.Registry) error {
	files := campaignFiles(dir)
	ldg, err := ledger.Open(files["ledger"])
	if err != nil {
		return err
	}
	defer ldg.Close()
	events, err := ldg.Events()
	if err != nil {
		return err
	}
	reconcileRegistry(reg, events)
	if len(reg.All()) == 0 {
		return nil
	}
	return reg.Save(dir)
}

// requireAdmission enforces the campaign contract and the snapshot digest
// before any round activity. A directory with families but no valid,
// authorized contract must never dispatch work.
func requireAdmission(dir string) error {
	files := campaignFiles(dir)
	campaign, err := contract.Load(files["contract"])
	if err != nil {
		return fmt.Errorf("admission: %w", err)
	}
	if err := campaign.Validate(); err != nil {
		return fmt.Errorf("admission: %w", err)
	}
	mani, err := manifest.Load(files["manifest"])
	if err != nil {
		return fmt.Errorf("admission: %w", err)
	}
	want := campaign.Target.SourceSnapshot
	if strings.HasPrefix(want, "sha256:") {
		want = strings.TrimPrefix(want, "sha256:")
	}
	if want == "" || want != mani.ArchiveSHA {
		return fmt.Errorf("admission: campaign source_snapshot does not match manifest digest")
	}
	if err := mani.Verify(campaign.Target.SourcePath); err != nil {
		return fmt.Errorf("admission: %w", err)
	}
	return nil
}

// reconcileRegistry makes registry.json consistent with the append-only
// ledger. The ledger is the single source of truth; registry.json is a
// materialized view that must survive a crash at any point in a command:
//   - family_added recreates families whose definitions were lost
//   - family_reopened updates the mechanism of record
//   - family_blocked and result_ingested(blocked) replay block transitions
//   - attempt counts are recomputed from request_published and
//     family_reopened events
//
// Exhausted families are never downgraded: exhaustion is a terminal human
// decision the ledger does not record.
func reconcileRegistry(reg *registry.Registry, events []ledger.Event) {
	attempts := make(map[string]int)
	for _, event := range events {
		family := event.Data["family"]
		if family == "" {
			continue
		}
		switch event.Type {
		case "family_added":
			if _, ok := reg.Get(family); !ok {
				_ = reg.Add(family, event.Data["mechanism"])
			}
		case "family_reopened":
			attempts[family]++
			if approach, ok := reg.Get(family); ok {
				approach.Mechanism = event.Data["mechanism"]
				_ = reg.Set(family, approach)
			}
		case "family_blocked":
			if approach, ok := reg.Get(family); ok && approach.Status == registry.Active {
				_ = reg.Block(family, event.Data["reason"])
			}
		case "request_published":
			attempts[family]++
		}
	}
	for family, count := range attempts {
		approach, ok := reg.Get(family)
		if !ok {
			continue
		}
		approach.Attempts = 1 + count
		_ = reg.Set(family, approach)
	}
	_ = coordinator.ReconcileFromLedger(reg, events)
}

func publishedIDs(events []ledger.Event, round int) map[string]bool {
	ids := make(map[string]bool)
	for _, event := range events {
		if event.Type == "request_published" && event.Data["round"] == fmt.Sprint(round) {
			ids[event.ID] = true
		}
	}
	return ids
}

func ingestedIDs(events []ledger.Event) map[string]bool {
	ids := make(map[string]bool)
	for _, event := range events {
		if event.Type == "result_ingested" {
			ids[event.ID] = true
		}
	}
	return ids
}

func roundPlanCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("round plan requires <campaign-dir> <max-workers>")
	}
	dir := args[0]
	if err := requireAdmission(dir); err != nil {
		return err
	}
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

	ldg, err := ledger.Open(files["ledger"])
	if err != nil {
		return err
	}
	defer ldg.Close()
	events, err := ldg.Events()
	if err != nil {
		return err
	}
	reconcileRegistry(reg, events)
	if len(reg.All()) == 0 {
		return errors.New("no approach families registered; use: vrh families add")
	}

	// Determine this round's family set. If a crash interrupted an earlier
	// attempt, recover the original plan verbatim so the retry publishes the
	// exact same set — recomputing from post-dispatch attempt counts could
	// select different families and break the round's worker bound.
	var plan []string
	if state.PendingRound == coord.Round && len(state.PendingPlan) > 0 {
		plan = validActiveFamilies(reg, state.PendingPlan)
	} else {
		plan = planFamilies(reg, coord.Round, maxWorkers)
	}

	published := publishedIDs(events, coord.Round)
	var todo []string
	for _, family := range plan {
		if !published[fmt.Sprintf("%s--r%d", family, coord.Round)] {
			todo = append(todo, family)
		}
	}

	if len(todo) == 0 {
		// Round fully planned (or nothing left to dispatch): advance.
		state.Round = coord.Round + 1
		state.PendingRound = 0
		state.PendingPlan = nil
		if err := saveRoundState(files["state"], state); err != nil {
			return err
		}
		if err := reg.Save(dir); err != nil {
			return err
		}
		fmt.Printf("round %d already fully planned; advanced to round %d\n", coord.Round, coord.Round+1)
		return nil
	}

	// Record the plan durably BEFORE publishing anything, so a crash leaves
	// the exact family set recoverable.
	if state.PendingRound != coord.Round || len(state.PendingPlan) == 0 {
		state.PendingRound = coord.Round
		state.PendingPlan = plan
		if err := saveRoundState(files["state"], state); err != nil {
			return err
		}
	}

	inbox, err := executor.NewInbox(files["inbox"])
	if err != nil {
		return err
	}
	for _, family := range todo {
		requestID := fmt.Sprintf("%s--r%d", family, coord.Round)
		request := worker.Request{
			ID:     requestID,
			Round:  coord.Round,
			Family: family,
			Goal:   "investigate " + family + " for primitives matching the campaign success criterion",
		}
		if err := inbox.Publish(request); err != nil {
			return err
		}
		if _, err := ldg.Append(requestID, "request_published", map[string]string{"round": fmt.Sprint(coord.Round), "family": family}); err != nil {
			return err
		}
	}
	// Reconcile again so the on-disk registry reflects the request_published
	// events this command just appended; otherwise the saved view lags the
	// ledger until the next command.
	events, err = ldg.Events()
	if err != nil {
		return err
	}
	reconcileRegistry(reg, events)
	if err := reg.Save(dir); err != nil {
		return err
	}
	// Advance past the planned round and clear the pending plan. If a crash
	// lands between reg.Save and this write, the retry recovers via the
	// pending plan and takes the "already fully planned" branch above.
	state.Round = coord.Round + 1
	state.PendingRound = 0
	state.PendingPlan = nil
	if err := saveRoundState(files["state"], state); err != nil {
		return err
	}
	fmt.Printf("round %d planned: dispatched %s\n", coord.Round, strings.Join(todo, ", "))
	fmt.Println("request envelopes written to inbox/requests/")
	return nil
}

// validActiveFamilies keeps only families that still exist and are active,
// in case a pending plan predates a manual block/exhaust.
func validActiveFamilies(reg *registry.Registry, families []string) []string {
	var out []string
	for _, family := range families {
		approach, ok := reg.Get(family)
		if ok && approach.Status == registry.Active {
			out = append(out, family)
		}
	}
	return out
}

// planFamilies mirrors the coordinator's dispatch order without mutating the
// registry, so admission checks can inspect it read-only.
func planFamilies(reg *registry.Registry, round, maxWorkers int) []string {
	state, err := coordinator.NewState(maxWorkers)
	if err != nil {
		return nil
	}
	state.Round = round
	clone := registry.New()
	for _, approach := range reg.All() {
		_ = clone.Add(approach.Family, approach.Mechanism)
		if approach.Status == registry.Blocked {
			_ = clone.Block(approach.Family, approach.BlockReason)
		} else if approach.Status == registry.Exhausted {
			_ = clone.Exhaust(approach.Family)
		}
		for i := 1; i < approach.Attempts; i++ {
			_ = clone.RecordDispatch(approach.Family)
		}
	}
	plan, err := state.Plan(clone)
	if err != nil {
		return nil
	}
	return plan.Dispatched
}

func roundIngestCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("round ingest requires <campaign-dir>")
	}
	dir := args[0]
	if err := requireAdmission(dir); err != nil {
		return err
	}
	files := campaignFiles(dir)

	ldg, err := ledger.Open(files["ledger"])
	if err != nil {
		return err
	}
	defer ldg.Close()
	events, err := ldg.Events()
	if err != nil {
		return err
	}

	reg, err := loadRegistry(dir)
	if err != nil {
		return err
	}
	// Reconcile first: if a previous ingest crashed after appending results
	// to the ledger but before saving the registry, replaying the ledger
	// restores the lost transitions before anything else runs.
	reconcileRegistry(reg, events)

	inbox, err := executor.NewInbox(files["inbox"])
	if err != nil {
		return err
	}
	outstanding, err := inbox.OutstandingRequests()
	if err != nil {
		return err
	}
	if len(outstanding) == 0 {
		return errors.New("no outstanding requests; run: vrh round plan")
	}
	collected, err := inbox.CollectResults(executor.DefaultGate(), outstanding)
	if err != nil {
		return err
	}

	ingested := ingestedIDs(events)
	var fresh []worker.Result
	for _, item := range collected {
		if ingested[item.Result.RequestID] {
			// Leftover envelope from a crashed ingest: its effect was already
			// replayed by reconcileRegistry; only the consume step is missing.
			continue
		}
		fresh = append(fresh, item.Result)
	}
	if len(fresh) > 0 {
		coord, err := coordinator.NewState(1)
		if err != nil {
			return err
		}
		if err := coord.Ingest(reg, outstanding, fresh); err != nil {
			return err
		}
		for _, result := range fresh {
			data := map[string]string{
				"status":   string(result.Status),
				"findings": fmt.Sprint(len(result.Findings)),
				"family":   outstanding[result.RequestID],
			}
			if result.BlockReason != "" {
				data["block_reason"] = result.BlockReason
			}
			if _, err := ldg.Append(result.RequestID, "result_ingested", data); err != nil {
				return err
			}
		}
	}
	if err := inbox.Consume(collected); err != nil {
		return err
	}
	if err := reg.Save(dir); err != nil {
		return err
	}
	fmt.Printf("ingested %d results\n", len(fresh))
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
