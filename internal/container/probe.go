package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CreateArgs builds a create-only invocation used to inspect HostConfig
// without executing anything inside the image.
func CreateArgs(kind string, spec Spec, name string) ([]string, error) {
	if err := spec.validateBinds(); err != nil {
		return nil, err
	}
	if !validContainerName(name) {
		return nil, fmt.Errorf("container name must be a vrh-* token")
	}
	iso, err := isolationFlags(kind)
	if err != nil {
		return nil, err
	}
	args := append([]string{"create", "--name=" + name}, iso...)
	args = append(args, bindMounts(spec)...)
	args = append(args, spec.Image)
	if err := forbidUnsafeArgs(args); err != nil {
		return nil, err
	}
	return args, nil
}

type inspectInfo struct {
	Name       string            `json:"Name"`
	HostConfig inspectHostConfig `json:"HostConfig"`
	Mounts     []inspectMount    `json:"Mounts"`
}

type inspectMount struct {
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
	Type        string `json:"Type"`
}

type inspectHostConfig struct {
	NetworkMode     string                     `json:"NetworkMode"`
	PidMode         string                     `json:"PidMode"`
	IpcMode         string                     `json:"IpcMode"`
	UTSMode         string                     `json:"UTSMode"`
	Privileged      bool                       `json:"Privileged"`
	ReadonlyRootfs  bool                       `json:"ReadonlyRootfs"`
	PublishAllPorts bool                       `json:"PublishAllPorts"`
	PortBindings    map[string]json.RawMessage `json:"PortBindings"`
	CapDrop         []string                   `json:"CapDrop"`
	CapAdd          []string                   `json:"CapAdd"`
	Devices         json.RawMessage            `json:"Devices"`
	SecurityOpt     []string                   `json:"SecurityOpt"`
	Memory          int64                      `json:"Memory"`
	MemorySwap      int64                      `json:"MemorySwap"`
	PidsLimit       int64                      `json:"PidsLimit"`
}

func certifyHostConfig(raw []byte, spec Spec) error {
	var info inspectInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("parse inspect: %w", err)
	}
	hc := info.HostConfig
	if !strings.EqualFold(hc.NetworkMode, "none") {
		return fmt.Errorf("container network is %q, want none", hc.NetworkMode)
	}
	if hostNamespace(hc.PidMode) {
		return fmt.Errorf("container pid namespace is %q", hc.PidMode)
	}
	if hostNamespace(hc.IpcMode) {
		return fmt.Errorf("container ipc namespace is %q", hc.IpcMode)
	}
	if hostNamespace(hc.UTSMode) {
		return fmt.Errorf("container uts namespace is %q", hc.UTSMode)
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
	if len(hc.CapAdd) > 0 {
		return fmt.Errorf("container adds capabilities: %v", hc.CapAdd)
	}
	if deviceCount(hc.Devices) > 0 {
		return fmt.Errorf("container has host devices")
	}
	if !hasNoNewPrivileges(hc.SecurityOpt) {
		return fmt.Errorf("container is missing no-new-privileges: %v", hc.SecurityOpt)
	}
	if hc.Memory <= 0 {
		return fmt.Errorf("container memory limit is unproven")
	}
	if hc.MemorySwap < 0 {
		return fmt.Errorf("container swap is unlimited")
	}
	if hc.MemorySwap > hc.Memory {
		return fmt.Errorf("container swap %d exceeds memory %d", hc.MemorySwap, hc.Memory)
	}
	if hc.PidsLimit <= 0 {
		return fmt.Errorf("container pids limit is unproven")
	}
	if spec.Snapshot != "" {
		if err := requireReadOnlyMount(info.Mounts, SnapshotMount); err != nil {
			return err
		}
	}
	if spec.Script != "" {
		if err := requireReadOnlyMount(info.Mounts, CaseMount); err != nil {
			return err
		}
	}
	return nil
}

func hostNamespace(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), "host")
}

func deviceCount(raw json.RawMessage) int {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0
	}
	var devices []json.RawMessage
	if err := json.Unmarshal(raw, &devices); err != nil {
		return 1
	}
	return len(devices)
}

func hasNoNewPrivileges(opts []string) bool {
	for _, opt := range opts {
		o := strings.ToLower(strings.TrimSpace(opt))
		if strings.Contains(o, "no-new-privileges") {
			return true
		}
	}
	return false
}

func requireReadOnlyMount(mounts []inspectMount, dest string) error {
	for _, m := range mounts {
		if m.Destination == dest {
			if m.RW {
				return fmt.Errorf("mount %s is writable", dest)
			}
			return nil
		}
	}
	return fmt.Errorf("missing read-only mount %s", dest)
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
// dropped capabilities, resource limits, no published ports, and
// read-only snapshot/script mounts. It does not execute the image, so
// Bash- or Node-only images can be certified.
func (rt Runtime) VerifyIsolation(image string) error {
	if err := rt.RequireImage(image); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "vrh-iso-")
	if err != nil {
		return fmt.Errorf("create isolation scratch: %w", err)
	}
	defer os.RemoveAll(dir)
	snap := filepath.Join(dir, "snap")
	script := filepath.Join(dir, "case")
	if err := os.Mkdir(snap, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(script, []byte("#\n"), 0600); err != nil {
		return err
	}
	spec := Spec{Image: image, Snapshot: snap, Script: script}
	name := UniqueName()
	args, err := CreateArgs(rt.Kind, spec, name)
	if err != nil {
		return err
	}
	createOut, err := rt.preflight(args...)
	if err != nil {
		return fmt.Errorf("create isolation probe: %s", strings.TrimSpace(string(createOut)))
	}
	cid := strings.TrimSpace(string(createOut))
	defer func() {
		rt.removeContainer(name, "")
		if cid != "" && cid != name {
			_, _ = rt.preflight("rm", "-f", cid)
		}
	}()
	if cid == "" {
		return fmt.Errorf("create isolation probe returned no container id")
	}

	raw, err := rt.preflight("inspect", name)
	if err != nil {
		return fmt.Errorf("inspect isolation probe: %s", strings.TrimSpace(string(raw)))
	}
	// docker inspect returns an array; podman may too.
	var many []json.RawMessage
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 {
		return certifyHostConfig(many[0], spec)
	}
	return certifyHostConfig(raw, spec)
}
