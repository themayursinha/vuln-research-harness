//go:build linux

package repro

import "testing"

func TestLandlockHandledFSABIBits(t *testing.T) {
	// ABI 4 added net rights only; IOCTL_DEV is ABI 5. Requesting bit 15
	// on ABI 4 makes landlock_create_ruleset return EINVAL.
	cases := []struct {
		abi  uintptr
		bits int
	}{
		{1, 13},
		{2, 14},
		{3, 15},
		{4, 15},
		{5, 16},
		{8, 16},
	}
	for _, tc := range cases {
		got := bitsSet(landlockHandledFS(tc.abi))
		if got != tc.bits {
			t.Errorf("abi %d: handled %d bits, want %d", tc.abi, got, tc.bits)
		}
	}
	if landlockHandledFS(4)&landlockFSIoctlDev != 0 {
		t.Fatal("ABI 4 must not handle LANDLOCK_ACCESS_FS_IOCTL_DEV")
	}
}

func bitsSet(v uint64) int {
	n := 0
	for v != 0 {
		n++
		v &= v - 1
	}
	return n
}
