package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/themayursinha/vuln-research-harness/internal/ledger"
)

// OutstandingFromLedger derives the outstanding request set from the ledger:
// a request is outstanding only when a request_published event records its
// dispatch and no result_ingested event records its answer. Files under requests/ are then verified against
// that set: every ledgered ID must have a matching envelope file, and every
// envelope file must correspond to a ledgered dispatch. This closes the gap
// where a hand-placed JSON file in inbox/requests could inject an arbitrary
// request/family pair into ingest.
func OutstandingFromLedger(inbox *Inbox, events []ledger.Event) (map[string]string, error) {
	dispatchedRaw := make(map[string]bool)
	dispatched := make(map[string]string)
	ingested := make(map[string]bool)
	for _, event := range events {
		switch event.Type {
		case "request_published":
			family := event.Data["family"]
			if family == "" {
				return nil, fmt.Errorf("ledger: request_published event for %s has no family", event.ID)
			}
			dispatchedRaw[event.ID] = true
			dispatched[event.ID] = family
		case "result_ingested":
			// The result was already applied to the registry; its request
			// must never re-enter the outstanding set, or a reopened family
			// could be re-blocked by replaying stale evidence.
			ingested[event.ID] = true
		}
	}
	for id := range ingested {
		delete(dispatched, id)
	}
	files, err := readRequestFiles(filepath.Join(inbox.dir, "requests"))
	if err != nil {
		return nil, err
	}
	outstanding := make(map[string]string)
	for id, family := range dispatched {
		envelopeFamily, ok := files[id]
		if !ok {
			continue // envelope not yet written; nothing to ingest
		}
		if envelopeFamily != family {
			return nil, fmt.Errorf("request %s envelope says family %q but ledger recorded %q", id, envelopeFamily, family)
		}
		outstanding[id] = family
	}
	for id := range files {
		// A consumed request's envelope file may legitimately remain if the
		// worker re-dropped it after ingestion; only unpublished files are
		// an error.
		if _, isDispatched := dispatchedRaw[id]; !isDispatched {
			return nil, fmt.Errorf("request file for %s has no request_published event; refusing to treat it as dispatched", id)
		}
	}
	return outstanding, nil
}

// readRequestFiles reads every .json envelope under requestsDir and maps the
// ID inside the content to the recorded family, so filenames never decide
// identity.
func readRequestFiles(requestsDir string) (map[string]string, error) {
	entries, err := os.ReadDir(requestsDir)
	if err != nil {
		return nil, fmt.Errorf("read requests: %w", err)
	}
	files := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(requestsDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var request struct {
			ID     string `json:"id"`
			Family string `json:"family"`
		}
		if err := json.Unmarshal(data, &request); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		if strings.TrimSpace(request.ID) == "" || strings.TrimSpace(request.Family) == "" {
			return nil, fmt.Errorf("%s: request id and family are required", entry.Name())
		}
		files[request.ID] = request.Family
	}
	return files, nil
}
