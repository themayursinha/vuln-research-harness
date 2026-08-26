package container

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/themayursinha/vuln-research-harness/internal/sandbox"
)

const loopbackProbe = `
import socket, threading
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(1)
port = s.getsockname()[1]
def serve():
    c, _ = s.accept()
    c.close()
t = threading.Thread(target=serve)
t.daemon = True
t.start()
c = socket.create_connection(("127.0.0.1", port), timeout=2)
print("LOOPBACK_OK")
c.close()
`

// VerifyIsolation proves the digest-pinned image is local, outbound DNS/TCP
// are blocked inside --network=none, and loopback still works for fixtures.
func (rt Runtime) VerifyIsolation(image string) error {
	if err := rt.RequireImage(image); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp("", "vrh-cprobe-")
	if err != nil {
		return fmt.Errorf("create probe workdir: %w", err)
	}
	defer os.RemoveAll(scratch)

	run := func(ctx context.Context, command string, args []string) ([]byte, error) {
		spec := Spec{Image: image, Command: append([]string{command}, args...)}
		cmd, err := rt.Command(ctx, spec, UniqueCIDFile(scratch))
		if err != nil {
			return nil, err
		}
		return cmd.CombinedOutput()
	}
	v, err := sandbox.VerifyWith(sandbox.DefaultNetworkProbes(), run)
	if err != nil {
		return err
	}
	if !v.Passed {
		return fmt.Errorf("container network isolation not verified: %s", strings.Join(v.Problems, "; "))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := run(ctx, "python3", []string{"-c", loopbackProbe})
	if err != nil {
		return fmt.Errorf("loopback probe failed to execute; isolation unproven: %v", err)
	}
	if !bytes.Contains(out, []byte("LOOPBACK_OK")) {
		return fmt.Errorf("loopback not usable inside the container; local fixtures would fail: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
