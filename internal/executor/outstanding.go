package executor

import (
	"crypto/sha256"
	"encoding/hex"
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
	expectedDigest := make(map[string]string)
	for _, event := range events {
		switch event.Type {
		case "request_published":
			family := event.Data["family"]
			if family == "" {
				return nil, fmt.Errorf("ledger: request_published event for %s has no family", event.ID)
			}
			dispatchedRaw[event.ID] = true
			dispatched[event.ID] = family
			if digest := event.Data["envelope_sha256"]; digest != "" {
				expectedDigest[event.ID] = digest
			}
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
	for id, file := range files {
		family, isDispatched := dispatched[id]
		if !isDispatched {
			if dispatchedRaw[id] {
				continue // consumed request's envelope re-dropped; not fatal
			}
			return nil, fmt.Errorf("request file for %s has no request_published event; refusing to treat it as dispatched", id)
		}
		if file.family != family {
			return nil, fmt.Errorf("request %s envelope says family %q but ledger recorded %q", id, file.family, family)
		}
		if want, ok := expectedDigest[id]; ok && file.digest != want {
			return nil, fmt.Errorf("request %s envelope digest mismatch: assignment altered after publication", id)
		}
		outstanding[id] = family
	}
	return outstanding, nil
}

type requestFile struct {
	family string
	digest string
}

// readRequestFiles reads every .json envelope under requestsDir and maps the
// ID inside the content to the recorded family and the digest of the complete
// serialized envelope, so filenames never decide identity and post-publication
// tampering with assignment fields is detectable.
func readRequestFiles(requestsDir string) (map[string]requestFile, error) {
	entries, err := os.ReadDir(requestsDir)
	if err != nil {
		return nil, fmt.Errorf("read requests: %w", err)
	}
	files := make(map[string]requestFile)
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
		sum := sha256.Sum256(data)
		files[request.ID] = requestFile{
			family: request.Family,
			digest: hex.EncodeToString(sum[:]),
		}
	}
	return files, nil
}
