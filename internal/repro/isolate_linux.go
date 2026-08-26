//go:build linux

package repro

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// sandboxInitArg is argv[1] of the isolated child. init() intercepts it
// before main (or testing.M) so the same binary can bring up the sandbox
// and exec the case interpreter. chmod bits are not a write barrier: the
// child is uid 0 in the user namespace, so Landlock is the immutability
// gate. Unprivileged mount namespaces are a dead end on kernels with
// apparmor_restrict_unprivileged_userns (tmpfs/bind return EACCES).
const sandboxInitArg = "__vrh_sandbox_init__"

const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
	landlockRulePathBeneath  = 1
	landlockCreateVersion    = 1
	prSetNoNewPrivs          = 38
	// oPath is omitted from syscall on linux/amd64; the value is arch-stable.
	oPath = 0x200000
)

const (
	landlockFSExecute = 1 << iota
	landlockFSWriteFile
	landlockFSReadFile
	landlockFSReadDir
	landlockFSRemoveDir
	landlockFSRemoveFile
	landlockFSMakeChar
	landlockFSMakeDir
	landlockFSMakeReg
	landlockFSMakeSock
	landlockFSMakeFIFO
	landlockFSMakeBlock
	landlockFSMakeSym
	landlockFSRefer
	landlockFSTruncate
	landlockFSIoctlDev
)

func init() {
	if len(os.Args) < 4 || os.Args[1] != sandboxInitArg {
		return
	}
	err := prepareSandboxAndExec(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "vrh-sandbox: %s\n", err)
	}
	os.Exit(sandboxFailExit)
}

func startIsolatedCommand(ctx context.Context, interpreter, script string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve vrh executable: %w", err)
	}
	cmd := exec.CommandContext(ctx, exe, sandboxInitArg, interpreter, script)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true,
		Pdeathsig:                  syscall.SIGKILL,
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return err
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}

func prepareSandboxAndExec(interpreter, script string) error {
	scratch := os.Getenv("VRH_SCRATCH")
	if scratch == "" {
		return fmt.Errorf("missing VRH_SCRATCH")
	}
	if os.Getenv("VRH_SNAPSHOT") == "" {
		return fmt.Errorf("missing VRH_SNAPSHOT")
	}
	bin, err := exec.LookPath(interpreter)
	if err != nil {
		return fmt.Errorf("interpreter: %w", err)
	}
	bringLoopbackUp()
	if err := restrictFS(scratch); err != nil {
		return err
	}
	return syscall.Exec(bin, []string{bin, script}, os.Environ())
}

func bringLoopbackUp() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	var ifr struct {
		name  [syscall.IFNAMSIZ]byte
		flags uint16
		_     [14]byte
	}
	copy(ifr.name[:], "lo")
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return
	}
	ifr.flags |= syscall.IFF_UP | syscall.IFF_RUNNING
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr)))
}

func restrictFS(scratch string) error {
	abi, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateVersion)
	if errno != 0 {
		return fmt.Errorf("landlock unavailable: %w", errno)
	}
	handled := landlockHandledFS(abi)
	readExec := (landlockFSExecute | landlockFSReadFile | landlockFSReadDir) & handled

	attr := handled
	rs, _, errno := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock ruleset: %w", errno)
	}
	defer syscall.Close(int(rs))

	if err := landlockAllow(int(rs), "/", readExec, handled); err != nil {
		return err
	}
	if err := landlockAllow(int(rs), scratch, handled, handled); err != nil {
		return err
	}
	if _, _, errno = syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	if _, _, errno = syscall.Syscall(sysLandlockRestrictSelf, rs, 0, 0); errno != 0 {
		return fmt.Errorf("landlock restrict: %w", errno)
	}
	return nil
}

func landlockHandledFS(abi uintptr) uint64 {
	bits := 13
	switch {
	case abi >= 4:
		bits = 16
	case abi == 3:
		bits = 15
	case abi == 2:
		bits = 14
	}
	return 1<<bits - 1
}

func landlockAllow(rs int, path string, access, handled uint64) error {
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer syscall.Close(fd)
	var buf [12]byte
	*(*uint64)(unsafe.Pointer(&buf[0])) = access & handled
	*(*int32)(unsafe.Pointer(&buf[8])) = int32(fd)
	_, _, errno := syscall.Syscall6(sysLandlockAddRule, uintptr(rs), landlockRulePathBeneath, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock rule %s: %w", path, errno)
	}
	return nil
}
