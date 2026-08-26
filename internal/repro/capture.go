package repro

import (
	"bytes"
	"crypto/sha256"
	"hash"
)

const maxKeptOutput = 1 << 20

// capture hashes every byte, scans for a marker, and retains only a bounded
// prefix so a runaway script cannot exhaust host memory.
type capture struct {
	hash   hash.Hash
	marker []byte
	pref   []byte
	found  bool
	kept   bytes.Buffer
}

func newCapture(marker string) *capture {
	return &capture{hash: sha256.New(), marker: []byte(marker)}
}

func (c *capture) Write(p []byte) (int, error) {
	_, _ = c.hash.Write(p)
	if len(c.marker) > 0 && !c.found {
		buf := append(c.pref, p...)
		c.found = bytes.Contains(buf, c.marker)
		keep := len(c.marker) - 1
		if keep < 0 {
			keep = 0
		}
		if len(buf) > keep {
			c.pref = append([]byte(nil), buf[len(buf)-keep:]...)
		} else {
			c.pref = append([]byte(nil), buf...)
		}
	}
	if c.kept.Len() < maxKeptOutput {
		n := maxKeptOutput - c.kept.Len()
		if len(p) < n {
			n = len(p)
		}
		_, _ = c.kept.Write(p[:n])
	}
	return len(p), nil
}

func (c *capture) sum() []byte {
	return c.hash.Sum(nil)
}
