//go:build windows

// Write a live kernel memory dump, as Task Manager's "Create live kernel
// memory dump file" does, so that a debugger can show the kernel stacks of
// threads stuck in system calls. The dump holds kernel memory only.
//
// Usage: go run livedump.go FILE

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procNtSystemDebugControl  = ntdll.NewProc("NtSystemDebugControl")
	procLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

const (
	sysDbgGetLiveKernelDump = 37    // SYSDBG_COMMAND
	liveSystemDump          = 0x161 // LIVE_SYSTEM_DUMP bug check code
	sePrivilegeEnabled      = 0x2   // SE_PRIVILEGE_ENABLED
	errorNotAllAssigned     = 1300  // ERROR_NOT_ALL_ASSIGNED
)

// liveDumpControl is SYSDBG_LIVEDUMP_CONTROL as of version 2. Version 1
// ends before SelectiveControl.
type liveDumpControl struct {
	Version           uint32
	BugCheckCode      uint32
	BugCheckParams    [4]uintptr
	DumpFileHandle    syscall.Handle
	CancelEventHandle syscall.Handle
	Flags             uint32
	AddPagesControl   uint32
	SelectiveControl  uintptr
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	LUID           struct {
		LowPart  uint32
		HighPart int32
	}
	Attributes uint32
}

func enablePrivilege(name string) error {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	var token syscall.Token
	err = syscall.OpenProcessToken(process, syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	tp := tokenPrivileges{PrivilegeCount: 1, Attributes: sePrivilegeEnabled}
	r, _, err := procLookupPrivilegeValueW.Call(
		0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&tp.LUID)))
	if r == 0 {
		return fmt.Errorf("LookupPrivilegeValue: %w", err)
	}
	r, _, err = procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %w", err)
	}
	// AdjustTokenPrivileges succeeds even when the token lacks the privilege.
	if err == syscall.Errno(errorNotAllAssigned) {
		return fmt.Errorf("AdjustTokenPrivileges: %w", err)
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: livedump FILE")
		os.Exit(2)
	}
	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		fmt.Fprintf(os.Stderr, "enabling SeDebugPrivilege: %v\n", err)
		os.Exit(1)
	}
	f, err := os.Create(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	ctl := liveDumpControl{
		BugCheckCode:   liveSystemDump,
		DumpFileHandle: syscall.Handle(f.Fd()),
	}
	versions := []struct {
		version uint32
		size    uintptr
	}{
		{1, unsafe.Offsetof(ctl.SelectiveControl)},
		{2, unsafe.Sizeof(ctl)},
	}
	for _, v := range versions {
		ctl.Version = v.version
		var n uint32
		status, _, _ := procNtSystemDebugControl.Call(
			sysDbgGetLiveKernelDump,
			uintptr(unsafe.Pointer(&ctl)), v.size,
			0, 0, uintptr(unsafe.Pointer(&n)))
		if status == 0 {
			fmt.Printf("wrote %s with control version %d\n", os.Args[1], v.version)
			return
		}
		fmt.Fprintf(os.Stderr, "control version %d: NTSTATUS 0x%08X\n", v.version, uint32(status))
	}
	os.Exit(1)
}
