// Package sandbox verifies the isolation a campaign runs under. The v1
// adapter checks network denial by executing probe commands in the campaign
// environment and refusing to certify anything it cannot prove.
package sandbox

import (
	"context"
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
socket.setdefaulttimeout(3)
try:
    socket.getaddrinfo("example.com", 443)
    print("NETWORK_OK")
except socket.timeout:
    print("TIMEOUT")
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
except socket.timeout:
    print("TIMEOUT")
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

// Runner executes one probe command and returns combined output.
type Runner func(ctx context.Context, command string, args []string) (output []byte, err error)

// VerifyNetwork runs the probes on the host with exec.Command.
func VerifyNetwork(probes []NetworkProbe) (Verification, error) {
	return VerifyWith(probes, func(ctx context.Context, command string, args []string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, command, args...)
		return cmd.CombinedOutput()
	})
}

// VerifyWith runs the probes through run. The boundary is certified only
// when every probe executes successfully and reports BLOCKED. A probe that
// cannot run, times out, or returns an inconclusive result leaves isolation
// unproven and fails certification.
func VerifyWith(probes []NetworkProbe, run Runner) (Verification, error) {
	v := Verification{Passed: true}
	if len(probes) == 0 {
		return Verification{Passed: false, Problems: []string{"no probes provided; isolation unproven"}}, nil
	}
	if run == nil {
		return Verification{Passed: false, Problems: []string{"no probe runner; isolation unproven"}}, nil
	}
	for _, probe := range probes {
		switch probe.Name {
		case "dns_resolution_blocked", "tcp_connect_blocked":
		default:
			return v, fmt.Errorf("unknown probe %q", probe.Name)
		}
		if probe.Timeout <= 0 {
			return v, fmt.Errorf("probe %q has no timeout", probe.Name)
		}

		ctx, cancel := context.WithTimeout(context.Background(), probe.Timeout)
		outBytes, err := run(ctx, probe.Command, probe.Args)
		blocked, problem := interpretProbe(probe.Name, string(outBytes), err, ctx.Err())
		cancel()
		if probe.Name == "dns_resolution_blocked" {
			v.DNSBlocked = blocked
		} else {
			v.TCPBlocked = blocked
		}
		if problem != "" {
			v.Passed = false
			v.Problems = append(v.Problems, problem)
		}
	}
	return v, nil
}

func interpretProbe(name, output string, runErr, ctxErr error) (blocked bool, problem string) {
	switch {
	case ctxErr == context.DeadlineExceeded:
		return false, fmt.Sprintf("probe %s timed out; isolation unproven", name)
	case runErr != nil:
		return false, fmt.Sprintf("probe %s failed to execute; isolation unproven: %v", name, runErr)
	case strings.Contains(output, "NETWORK_OK"):
		return false, fmt.Sprintf("probe %s found live network access", name)
	case strings.Contains(output, "TIMEOUT"):
		return false, fmt.Sprintf("probe %s timed out; isolation unproven", name)
	case strings.Contains(output, "BLOCKED"):
		return true, ""
	default:
		return false, fmt.Sprintf("probe %s produced no conclusive result; isolation unproven", name)
	}
}
