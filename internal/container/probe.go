package container

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CreateArgs builds a create-only invocation used to inspect HostConfig
// without executing anything inside the image.
func CreateArgs(kind, image string) ([]string, error) {
	if !PinnedImage(image) {
		return nil, fmt.Errorf("container image must be digest-pinned (@sha256:...); got %q", image)
	}
	iso, err := isolationFlags(kind)
	if err != nil {
		return nil, err
	}
	args := append([]string{"create"}, iso...)
	args = append(args, image)
	if err := forbidUnsafeArgs(args); err != nil {
		return nil, err
	}
	return args, nil
}

type inspectInfo struct {
	HostConfig inspectHostConfig `json:"HostConfig"`
}

type inspectHostConfig struct {
	NetworkMode     string                     `json:"NetworkMode"`
	Privileged      bool                       `json:"Privileged"`
	ReadonlyRootfs  bool                       `json:"ReadonlyRootfs"`
	PublishAllPorts bool                       `json:"PublishAllPorts"`
	PortBindings    map[string]json.RawMessage `json:"PortBindings"`
	CapDrop         []string                   `json:"CapDrop"`
}

func certifyHostConfig(raw []byte) error {
	var info inspectInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("parse inspect: %w", err)
	}
	hc := info.HostConfig
	if hc.NetworkMode != "none" {
		return fmt.Errorf("container network is %q, want none", hc.NetworkMode)
	}
	if hc.Privileged {
		return fmt.Errorf("container is privileged")
	}
	if !hc.ReadonlyRootfs {
		return fmt.Errorf("container rootfs is not read-only")
	}
	if hc.PublishAllPorts || len(hc.PortBindings) > 0 {
		return fmt.Errorf("container publishes ports")
	}
	if !capDropAll(hc.CapDrop) {
		return fmt.Errorf("container did not drop all capabilities: %v", hc.CapDrop)
	}
	return nil
}

func capDropAll(drop []string) bool {
	for _, cap := range drop {
		if strings.EqualFold(cap, "ALL") {
			return true
		}
	}
	return false
}

// VerifyIsolation proves the digest-pinned image is local and that a
// created container actually received network=none, a read-only rootfs,
// dropped capabilities, and no published ports. It does not execute the
// image, so Bash- or Node-only images can be certified.
func (rt Runtime) VerifyIsolation(image string) error {
	if err := rt.RequireImage(image); err != nil {
		return err
	}
	args, err := CreateArgs(rt.Kind, image)
	if err != nil {
		return err
	}
	create := exec.Command(rt.Bin, args...)
	create.Env = clientEnv()
	out, err := create.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create isolation probe: %s", strings.TrimSpace(string(out)))
	}
	cid := strings.TrimSpace(string(out))
	if cid == "" {
		return fmt.Errorf("create isolation probe returned no container id")
	}
	defer func() {
		rm := exec.Command(rt.Bin, "rm", "-f", cid)
		rm.Env = clientEnv()
		_ = rm.Run()
	}()

	inspect := exec.Command(rt.Bin, "inspect", cid)
	inspect.Env = clientEnv()
	raw, err := inspect.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect isolation probe: %s", strings.TrimSpace(string(raw)))
	}
	// docker inspect returns an array; podman may too.
	var many []json.RawMessage
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 {
		return certifyHostConfig(many[0])
	}
	return certifyHostConfig(raw)
}
