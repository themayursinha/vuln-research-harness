package sandbox

import (
	"strings"
	"testing"
	"time"
)

func blockedProbes() []NetworkProbe {
	return []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "echo", Args: []string{"BLOCKED"}, Timeout: time.Second},
		{Name: "tcp_connect_blocked", Command: "echo", Args: []string{"BLOCKED"}, Timeout: time.Second},
	}
}

func TestVerifyNetworkFailsOpenProbes(t *testing.T) {
	probes := []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "echo", Args: []string{"NETWORK_OK"}, Timeout: time.Second},
		{Name: "tcp_connect_blocked", Command: "echo", Args: []string{"BLOCKED"}, Timeout: time.Second},
	}
	v, err := VerifyNetwork(probes)
	if err != nil {
		t.Fatal(err)
	}
	if v.Passed {
		t.Fatal("verification passed despite live DNS probe")
	}
	if v.DNSBlocked {
		t.Fatal("live DNS probe must not be recorded as blocked")
	}
	if len(v.Problems) == 0 {
		t.Fatal("no problem recorded for the failing probe")
	}
}

func TestVerifyNetworkPassesAllBlocked(t *testing.T) {
	v, err := VerifyNetwork(blockedProbes())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Passed || !v.DNSBlocked || !v.TCPBlocked {
		t.Fatalf("expected pass with both blocked: %+v", v)
	}
}

func TestVerifyNetworkRejectsUnknownProbe(t *testing.T) {
	probes := []NetworkProbe{{Name: "carrier_pigeon", Command: "echo", Timeout: time.Second}}
	if _, err := VerifyNetwork(probes); err == nil {
		t.Fatal("unknown probe accepted")
	}
}

func TestVerifyNetworkFailsWhenProbeCannotExecute(t *testing.T) {
	probes := []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "false", Timeout: time.Second},
		{Name: "tcp_connect_blocked", Command: "false", Timeout: time.Second},
	}
	v, err := VerifyNetwork(probes)
	if err != nil {
		t.Fatal(err)
	}
	if v.Passed || v.DNSBlocked || v.TCPBlocked {
		t.Fatalf("unrunnable probes must fail certification, got %+v", v)
	}
	if len(v.Problems) == 0 {
		t.Fatal("expected problems for unrunnable probes")
	}
}

func TestVerifyNetworkFailsWhenProbeTimesOut(t *testing.T) {
	probes := []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "sleep", Args: []string{"10"}, Timeout: 50 * time.Millisecond},
		{Name: "tcp_connect_blocked", Command: "echo", Args: []string{"BLOCKED"}, Timeout: time.Second},
	}
	v, err := VerifyNetwork(probes)
	if err != nil {
		t.Fatal(err)
	}
	if v.Passed || v.DNSBlocked {
		t.Fatalf("timed-out probe must not count as blocked, got %+v", v)
	}
	found := false
	for _, problem := range v.Problems {
		if strings.Contains(problem, "timed out") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected timeout problem, got %+v", v.Problems)
	}
}

func TestVerifyWithNilRunner(t *testing.T) {
	v, err := VerifyWith(blockedProbes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.Passed {
		t.Fatal("nil runner must not certify isolation")
	}
}

func TestVerifyNetworkRejectsProbeWithoutTimeout(t *testing.T) {
	probes := []NetworkProbe{{Name: "dns_resolution_blocked", Command: "echo", Args: []string{"BLOCKED"}}}
	if _, err := VerifyNetwork(probes); err == nil {
		t.Fatal("probe with no timeout accepted")
	}
}

func TestVerifyNetworkTreatsPythonTimeoutAsUnproven(t *testing.T) {
	probes := []NetworkProbe{
		{Name: "dns_resolution_blocked", Command: "echo", Args: []string{"TIMEOUT"}, Timeout: time.Second},
		{Name: "tcp_connect_blocked", Command: "echo", Args: []string{"BLOCKED"}, Timeout: time.Second},
	}
	v, err := VerifyNetwork(probes)
	if err != nil {
		t.Fatal(err)
	}
	if v.Passed || v.DNSBlocked {
		t.Fatalf("python TIMEOUT must not certify isolation, got %+v", v)
	}
}
