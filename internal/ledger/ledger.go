package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type Event struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Occurred time.Time         `json:"occurred_at"`
	Data     map[string]string `json:"data,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

type unsignedEvent struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Occurred time.Time         `json:"occurred_at"`
	Data     map[string]string `json:"data,omitempty"`
	PrevHash string            `json:"prev_hash"`
}

type Ledger struct {
	file     *os.File
	lastHash string
}

func Open(path string) (*Ledger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open ledger: %w", err)
	}
	ledger := &Ledger{file: file}
	if err := ledger.verify(); err != nil {
		file.Close()
		return nil, err
	}
	return ledger, nil
}

func (l *Ledger) Close() error { return l.file.Close() }

func (l *Ledger) Append(id, eventType string, data map[string]string) (Event, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(eventType) == "" {
		return Event{}, fmt.Errorf("event id and type are required")
	}
	event := Event{ID: id, Type: eventType, Occurred: time.Now().UTC(), Data: data, PrevHash: l.lastHash}
	event.Hash = hashEvent(event)
	line, err := json.Marshal(event)
	if err != nil {
		return Event{}, fmt.Errorf("encode event: %w", err)
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return Event{}, fmt.Errorf("append event: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return Event{}, fmt.Errorf("sync ledger: %w", err)
	}
	l.lastHash = event.Hash
	return event, nil
}

func (l *Ledger) verify() error {
	if _, err := l.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek ledger: %w", err)
	}
	scanner := bufio.NewScanner(l.file)
	var previous string
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("ledger line %d: malformed event: %w", lineNumber, err)
		}
		if event.PrevHash != previous {
			return fmt.Errorf("ledger line %d: previous hash mismatch", lineNumber)
		}
		if event.Hash == "" || event.Hash != hashEvent(event) {
			return fmt.Errorf("ledger line %d: hash mismatch", lineNumber)
		}
		previous = event.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read ledger: %w", err)
	}
	if _, err := l.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek ledger end: %w", err)
	}
	l.lastHash = previous
	return nil
}

func hashEvent(event Event) string {
	unsigned := unsignedEvent{ID: event.ID, Type: event.Type, Occurred: event.Occurred, Data: event.Data, PrevHash: event.PrevHash}
	data, _ := json.Marshal(unsigned)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
