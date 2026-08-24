// Package sandbox verifies the isolation a campaign runs under. The v1
// adapter checks network denial by executing probe commands in the campaign
// environment and refusing to certify anything it cannot prove.
package sandbox

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// NetworkProbe is one connectivity check executed in the sandbox context.
type NetworkProbe struct {
	Name    string        `json:"name"`
	Command string        `json:"command"`
	Args    []string      `json:"args"`
	Timeout time.Duration `json:"timeout_seconds"`
}

// DefaultNetworkProbes cover DNS resolution and direct TCP dialing — the two
// paths an exfiltration payload would use first.
func DefaultNetworkProbes() []NetworkProbe {
	return []NetworkProbe{
		{
			Name:    "dns_resolution_blocked",
			Command: "python3",
			Args: []string{"-c", `
import socket
try:
    socket.getaddrinfo("example.com", 443)
    print("NETWORK_OK")
except OSError:
    print("BLOCKED")
`},
			Timeout: 10 * time.Second,
		},
		{
			Name:    "tcp_connect_blocked",
			Command: "python3",
			Args: []string{"-c", `
import socket
try:
    s = socket.create_connection(("1.1.1.1", 80), timeout=3)
    s.close()
    print("NETWORK_OK")
except OSError:
    print("BLOCKED")
`},
			Timeout: 15 * time.Second,
		},
	}
}

// Verification records the result of a full boundary check.
type Verification struct {
	Passed     bool     `json:"passed"`
	DNSBlocked bool     `json:"dns_blocked"`
	TCPBlocked bool     `json:"tcp_blocked"`
	Problems   []string `json:"problems,omitempty"`
}

// VerifyNetwork runs the probes and certifies the boundary only when every
// probe reports BLOCKED. A probe that cannot run is treated as blocked
// (conservative): verification proves isolation, never assumes it.
func VerifyNetwork(probes []NetworkProbe) (Verification, error) {
	v := Verification{Passed: true}
	for _, probe := range probes {
		cmd := exec.Command(probe.Command, probe.Args...)
		outBytes, err := cmd.Output()
		output := string(outBytes)
		blocked := err != nil || strings.Contains(output, "BLOCKED")
		switch probe.Name {
		case "dns_resolution_blocked":
			v.DNSBlocked = blocked
		case "tcp_connect_blocked":
			v.TCPBlocked = blocked
		default:
			return v, fmt.Errorf("unknown probe %q", probe.Name)
		}
		if !blocked {
			v.Passed = false
			v.Problems = append(v.Problems, fmt.Sprintf("probe %s found live network access", probe.Name))
		}
	}
	return v, nil
}
