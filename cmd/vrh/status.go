package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/themayursinha/vuln-research-harness/internal/executor"
)

func campaignStatusCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("campaign status requires <campaign-dir>")
	}
	dir := args[0]
	events, err := ledgerEventsFor(dir)
	if err != nil {
		return err
	}

	reg, err := loadRegistry(dir, events)
	if err != nil {
		return err
	}
	reconcileRegistry(reg, events)

	fmt.Printf("campaign: %s\n", dir)

	files := campaignFiles(dir)
	if data, err := os.ReadFile(files["state"]); err == nil {
		var state roundState
		if err := json.Unmarshal(data, &state); err == nil && state.Round > 0 {
			fmt.Printf("round: %d (max_workers=%d)\n", state.Round, state.MaxWorkers)
			if state.PendingRound > 0 && len(state.PendingPlan) > 0 {
				fmt.Printf("pending round %d: %s\n", state.PendingRound, joinComma(state.PendingPlan))
			}
		}
	}

	approaches := reg.All()
	if len(approaches) > 0 {
		fmt.Println("families:")
		for _, approach := range approaches {
			fmt.Printf("  %-8s %-20s attempts=%d  %s\n", approach.Status, approach.Family, approach.Attempts, approach.Mechanism)
		}
	}

	inbox, err := executor.NewInbox(files["inbox"])
	if err != nil {
		return err
	}
	outstanding, err := executor.OutstandingFromLedger(inbox, events)
	if err != nil {
		return err
	}
	fmt.Printf("outstanding requests: %d\n", len(outstanding))
	if len(outstanding) > 0 {
		ids := make([]string, 0, len(outstanding))
		for id := range outstanding {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Printf("  %s (%s)\n", id, outstanding[id])
		}
	}

	var reproRuns, validations int
	for _, event := range events {
		switch event.Type {
		case "reproduction_run":
			reproRuns++
		case "validation_verdict":
			validations++
		}
	}
	fmt.Printf("ledger: %d reproduction_run, %d validation_verdict\n", reproRuns, validations)

	for _, event := range events {
		if event.Type != "reproduction_run" {
			continue
		}
		fmt.Printf("  repro %s  cases=%s  reproduced=%s  %s\n",
			event.Occurred.Format("2006-01-02T15:04:05Z"),
			event.Data["case_ids"],
			event.Data["reproduced_count"],
			event.Data["outcomes_digest"],
		)
	}
	for _, event := range events {
		if event.Type != "validation_verdict" {
			continue
		}
		fmt.Printf("  validation %s  finding=%s  verdict=%s  attempts=%s  %s\n",
			event.Occurred.Format("2006-01-02T15:04:05Z"),
			event.Data["finding_id"],
			event.Data["verdict"],
			event.Data["attempts"],
			event.Data["report_digest"],
		)
	}
	return nil
}

func joinComma(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := items[0]
	for _, item := range items[1:] {
		out += ", " + item
	}
	return out
}
