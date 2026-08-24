package sandbox

import "testing"

func TestVerifyNetworkFailsOpenProbes(t *testing.T) {
	// A probe that reports NETWORK_OK means live access: verification must fail.
	probes := []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "echo", Args: []string{"NETWORK_OK"}},
		{Name: "tcp_connect_blocked", Command: "echo", Args: []string{"BLOCKED"}},
	}
	v, err := VerifyNetwork(probes)
	if err != nil {
		t.Fatal(err)
	}
	if v.Passed {
		t.Fatal("verification passed despite live DNS probe")
	}
	if len(v.Problems) == 0 {
		t.Fatal("no problem recorded for the failing probe")
	}
}

func TestVerifyNetworkPassesAllBlocked(t *testing.T) {
	probes := []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "echo", Args: []string{"BLOCKED"}},
		{Name: "tcp_connect_blocked", Command: "echo", Args: []string{"BLOCKED"}},
	}
	v, err := VerifyNetwork(probes)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Passed || !v.DNSBlocked || !v.TCPBlocked {
		t.Fatalf("expected pass with both blocked: %+v", v)
	}
}

func TestVerifyNetworkRejectsUnknownProbe(t *testing.T) {
	probes := []NetworkProbe{{Name: "carrier_pigeon", Command: "echo"}}
	if _, err := VerifyNetwork(probes); err == nil {
		t.Fatal("unknown probe accepted")
	}
}

func TestVerifyNetworkTreatsProbeErrorAsBlocked(t *testing.T) {
	// A command that cannot run (nonzero exit) counts as BLOCKED,
	// never as a silent pass — verification proves isolation or fails.
	probes := []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "false"},
		{Name: "tcp_connect_blocked", Command: "false"},
	}
	v, err := VerifyNetwork(probes)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Passed {
		t.Fatalf("erroring probes are conservative-blocked, got %+v", v)
	}
}
