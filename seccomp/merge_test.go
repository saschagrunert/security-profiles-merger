/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package seccomp_test

import (
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

const (
	syscallRead  = "read"
	syscallWrite = "write"
	syscallOpen  = "open"
	syscallClone = "clone"
)

func TestIntersectEmpty(t *testing.T) {
	t.Parallel()

	_, err := seccomp.Intersect()
	if err == nil {
		t.Fatal("expected error for empty profiles")
	}
}

func TestIntersectNil(t *testing.T) {
	t.Parallel()

	_, err := seccomp.Intersect(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestIntersectSingleProfile(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf("default action = %q, want %q", result.DefaultAction, specs.ActErrno)
	}

	if len(result.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall entry, got %d", len(result.Syscalls))
	}

	if len(result.Syscalls[0].Names) != 2 {
		t.Fatalf("expected 2 names in syscall entry, got %d", len(result.Syscalls[0].Names))
	}
}

func TestIntersectDefaultActions(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf(
			"default action = %q, want %q (more restrictive)",
			result.DefaultAction,
			specs.ActErrno,
		)
	}
}

func TestIntersectOverlappingSyscalls(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action, ok := syscallMap[syscallRead]; !ok || action != specs.ActAllow {
		t.Errorf("read: got %q, want %q", action, specs.ActAllow)
	}

	if action, ok := syscallMap[syscallWrite]; !ok || action != specs.ActLog {
		t.Errorf("write: got %q, want %q (more restrictive)", action, specs.ActLog)
	}

	if _, ok := syscallMap[syscallOpen]; ok {
		t.Error("open should not be in the result (matches merged default action)")
	}
}

func TestIntersectDifferentArgsDenied(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x20000, Op: specs.OpMaskedEqual}},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			if name == syscallClone {
				found = true

				if syscall.Action != specs.ActKillProcess {
					t.Errorf(
						"clone action = %q, want %q (conservative denial)",
						syscall.Action,
						specs.ActKillProcess,
					)
				}

				if len(syscall.Args) != 0 {
					t.Errorf(
						"clone should have no args after conservative denial, got %d",
						len(syscall.Args),
					)
				}
			}
		}
	}

	if !found {
		t.Error("clone not found in result")
	}
}

func TestIntersectIdenticalArgs(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{
		{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
	}

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			if name == syscallClone {
				found = true

				if syscall.Action != specs.ActAllow {
					t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
				}

				if len(syscall.Args) != 1 {
					t.Errorf("clone args count = %d, want 1", len(syscall.Args))
				}
			}
		}
	}

	if !found {
		t.Error("clone not found in result")
	}
}

func TestUnionOverlappingSyscalls(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action := syscallMap[syscallRead]; action != specs.ActAllow {
		t.Errorf("read: got %q, want %q (less restrictive)", action, specs.ActAllow)
	}

	if action := syscallMap[syscallWrite]; action != specs.ActAllow {
		t.Errorf("write: got %q, want %q", action, specs.ActAllow)
	}
}

func TestUnionDefaultActions(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActKillProcess}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf(
			"default action = %q, want %q (less restrictive)",
			result.DefaultAction,
			specs.ActErrno,
		)
	}
}

func TestIntersectArchitectures(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchARM},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchAARCH64},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Architectures) != 1 || result.Architectures[0] != specs.ArchX86_64 {
		t.Errorf("architectures = %v, want [%v]", result.Architectures, specs.ArchX86_64)
	}
}

func TestUnionArchitectures(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchARM},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Architectures) != 2 {
		t.Errorf("architectures count = %d, want 2", len(result.Architectures))
	}
}

func TestIntersectMultiNameNormalization(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite, syscallOpen}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action := syscallMap[syscallRead]; action != specs.ActAllow {
		t.Errorf("read: got %q, want %q", action, specs.ActAllow)
	}

	if action := syscallMap[syscallWrite]; action != specs.ActLog {
		t.Errorf("write: got %q, want %q", action, specs.ActLog)
	}
}

func uintPtr(val uint) *uint { return &val }

func TestNilProfileAtIndex(t *testing.T) {
	t.Parallel()

	valid := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	_, err := seccomp.Intersect(valid, nil)
	if err == nil {
		t.Fatal("expected error for nil profile at index 1")
	}

	_, err = seccomp.Union(valid, nil)
	if err == nil {
		t.Fatal("expected error for nil profile at index 1 (union)")
	}
}

func TestUnionWithIdenticalArgs(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{
		{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
	}

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 1 {
				t.Errorf("clone args count = %d, want 1", len(syscall.Args))
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestUnionWithDifferentArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x20000, Op: specs.OpMaskedEqual}},
		}},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 2 {
				t.Errorf("clone args count = %d, want 2 (combined)", len(syscall.Args))
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestUnionWithOneEmptyArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if len(syscall.Args) != 0 {
				t.Errorf(
					"clone args count = %d, want 0 (union drops args when one side has none)",
					len(syscall.Args),
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectOneHasArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 1 {
				t.Errorf(
					"clone args count = %d, want 1 (intersect keeps args from the side that has them)",
					len(syscall.Args),
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectFlags(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Flags) != 1 || result.Flags[0] != specs.LinuxSeccompFlagLog {
		t.Errorf("flags = %v, want [%v]", result.Flags, specs.LinuxSeccompFlagLog)
	}
}

func TestIntersectFlagsOneEmpty(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
	}

	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Flags) != 0 {
		t.Errorf("flags = %v, want empty (intersect with empty)", result.Flags)
	}
}

func TestUnionFlags(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Flags) != 2 {
		t.Errorf("flags count = %d, want 2", len(result.Flags))
	}
}

func TestIntersectErrnoRet(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(1),
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActAllow,
		DefaultErrnoRet: uintPtr(2),
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet == nil || *result.DefaultErrnoRet != 1 {
		t.Errorf("DefaultErrnoRet = %v, want 1", result.DefaultErrnoRet)
	}
}

func TestUnionErrnoRet(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(1),
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActAllow,
		DefaultErrnoRet: uintPtr(2),
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet == nil || *result.DefaultErrnoRet != 2 {
		t.Errorf("DefaultErrnoRet = %v, want 2", result.DefaultErrnoRet)
	}
}

func TestErrnoRetNil(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet != nil {
		t.Errorf("DefaultErrnoRet = %v, want nil", result.DefaultErrnoRet)
	}
}

func TestCloneProfilePreservesErrnoRet(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(42),
		Syscalls: []specs.LinuxSyscall{
			{
				Names:    []string{syscallRead},
				Action:   specs.ActErrno,
				ErrnoRet: uintPtr(13),
			},
		},
	}

	result, err := seccomp.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet == nil || *result.DefaultErrnoRet != 42 {
		t.Errorf("DefaultErrnoRet = %v, want 42", result.DefaultErrnoRet)
	}

	if len(result.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(result.Syscalls))
	}

	if result.Syscalls[0].ErrnoRet == nil || *result.Syscalls[0].ErrnoRet != 13 {
		t.Errorf("Syscall ErrnoRet = %v, want 13", result.Syscalls[0].ErrnoRet)
	}
}

func TestNormalizeDuplicateSyscalls(t *testing.T) {
	t.Parallel()

	t.Run("intersect", func(t *testing.T) {
		t.Parallel()

		left := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		}

		right := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
			},
		}

		result, err := seccomp.Intersect(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertSyscallAction(t, result, syscallRead, specs.ActLog)
	})

	t.Run("union", func(t *testing.T) {
		t.Parallel()

		left := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActLog},
				{Names: []string{syscallRead}, Action: specs.ActAllow},
			},
		}

		right := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		}

		result, err := seccomp.Union(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertSyscallAction(t, result, syscallRead, specs.ActAllow)
	})
}

func assertSyscallAction(
	t *testing.T,
	profile *specs.LinuxSeccomp,
	name string,
	want specs.LinuxSeccompAction,
) {
	t.Helper()

	for _, syscall := range profile.Syscalls {
		if slices.Contains(syscall.Names, name) {
			if syscall.Action != want {
				t.Errorf("%s action = %q, want %q", name, syscall.Action, want)
			}

			return
		}
	}

	t.Errorf("%s not found in result", name)
}

func TestIntersectMatchedSyscallEqualsDefault(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActErrno},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			if name == syscallWrite {
				t.Error("write should be eliminated (merged action matches default)")
			}
		}
	}
}

func TestUnionSyscallOnlyInOne(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActAllow)
}

func TestIntersectSyscallWithErrnoRet(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(1)},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog, ErrnoRet: uintPtr(2)},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			if syscall.Action != specs.ActErrno {
				t.Errorf("read action = %q, want %q", syscall.Action, specs.ActErrno)
			}

			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 1 {
				t.Errorf("read ErrnoRet = %v, want 1", syscall.ErrnoRet)
			}

			return
		}
	}

	t.Error("read not found in result")
}

func TestIntersectArchitecturesOneEmpty(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
	}

	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Architectures) != 1 || result.Architectures[0] != specs.ArchX86_64 {
		t.Errorf(
			"architectures = %v, want [%v] (intersect with empty keeps all)",
			result.Architectures, specs.ArchX86_64,
		)
	}
}

func TestMergeDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(1),
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	origLeftNames := slices.Clone(left.Syscalls[0].Names)
	origDefaultErrnoRet := *left.DefaultErrnoRet

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(left.Syscalls[0].Names, origLeftNames) {
		t.Error("Intersect mutated first input syscall names")
	}

	if *left.DefaultErrnoRet != origDefaultErrnoRet {
		t.Error("Intersect mutated first input DefaultErrnoRet")
	}

	if result.DefaultErrnoRet == left.DefaultErrnoRet {
		t.Error("result shares DefaultErrnoRet pointer with input")
	}
}

func TestUnionThreeProfiles(t *testing.T) {
	t.Parallel()

	first := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	second := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	third := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf(
			"default action = %q, want %q (least restrictive)",
			result.DefaultAction, specs.ActErrno,
		)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActAllow)
	assertSyscallAction(t, result, syscallWrite, specs.ActAllow)
	assertSyscallAction(t, result, syscallOpen, specs.ActAllow)
}

func TestIntersectListenerPreservation(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/listener.sock",
		ListenerMetadata: "metadata-left",
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/other.sock",
		ListenerMetadata: "metadata-right",
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ListenerPath != "/run/listener.sock" {
		t.Errorf(
			"ListenerPath = %q, want %q (from first profile)",
			result.ListenerPath, "/run/listener.sock",
		)
	}

	if result.ListenerMetadata != "metadata-left" {
		t.Errorf(
			"ListenerMetadata = %q, want %q (from first profile)",
			result.ListenerMetadata, "metadata-left",
		)
	}
}

func TestIntersectActKillAlias(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActKill},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActKillThread},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActKill)
}

func TestIntersectSyscallErrnoRetTieBreaking(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(1)},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(2)},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 1 {
				t.Errorf(
					"read ErrnoRet = %v, want 1 (leftmost wins when actions are equal)",
					syscall.ErrnoRet,
				)
			}

			return
		}
	}

	t.Error("read not found in result")
}

func TestIntersectOneHasArgsReverse(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 1 {
				t.Errorf(
					"clone args count = %d, want 1 (intersect keeps args from the side that has them)",
					len(syscall.Args),
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestMergeErrnoRetLeftNilWhenActionsEqual(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: nil,
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(42),
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet != nil {
		t.Errorf(
			"DefaultErrnoRet = %v, want nil (leftmost wins when actions are equal)",
			*result.DefaultErrnoRet,
		)
	}
}

func TestUnmatchedSyscallClearsErrnoRetOnActionChange(t *testing.T) {
	t.Parallel()

	// Left has "read" at ActAllow+ErrnoRet=42, default ActKillProcess.
	// Right has default ActErrno, no "read" entry.
	// Intersect: effective = MoreRestrictive(ActAllow, ActErrno) = ActErrno.
	// Since ActErrno != ActAllow, ErrnoRet must be cleared.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow, ErrnoRet: uintPtr(42)},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			if syscall.Action != specs.ActErrno {
				t.Errorf("read action = %q, want %q", syscall.Action, specs.ActErrno)
			}

			if syscall.ErrnoRet != nil {
				t.Errorf(
					"read ErrnoRet = %v, want nil (action came from other default)",
					*syscall.ErrnoRet,
				)
			}

			return
		}
	}

	t.Error("read not found in result")
}

func TestIntersectArgsDifferentIndices(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 1, Value: 42, Op: specs.OpEqualTo}},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 2 {
				t.Fatalf(
					"clone args count = %d, want 2 (combined from different indices)",
					len(syscall.Args),
				)
			}

			if syscall.Args[0].Index != 0 || syscall.Args[1].Index != 1 {
				t.Errorf(
					"args indices = [%d, %d], want [0, 1] (sorted by index)",
					syscall.Args[0].Index, syscall.Args[1].Index,
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectArgsSameIndexDifferentValues(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				{Index: 1, Value: 42, Op: specs.OpEqualTo},
			},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x20000, Op: specs.OpMaskedEqual},
				{Index: 1, Value: 42, Op: specs.OpEqualTo},
			},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActKillProcess {
				t.Errorf(
					"clone action = %q, want %q (conservative denial)",
					syscall.Action,
					specs.ActKillProcess,
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectArgsMixedIndices(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				{Index: 2, Value: 100, Op: specs.OpGreaterThan},
			},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				{Index: 1, Value: 42, Op: specs.OpEqualTo},
			},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 3 {
				t.Fatalf(
					"clone args count = %d, want 3 (shared index 0 + unique indices 1 and 2)",
					len(syscall.Args),
				)
			}

			for idx := 1; idx < len(syscall.Args); idx++ {
				if syscall.Args[idx].Index < syscall.Args[idx-1].Index {
					t.Error("args not sorted by index")
				}
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectArgsSameIndexDifferentOrder(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, Op: specs.OpEqualTo},
				{Index: 0, Value: 2, Op: specs.OpEqualTo},
			},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 2, Op: specs.OpEqualTo},
				{Index: 0, Value: 1, Op: specs.OpEqualTo},
			},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf(
					"clone action = %q, want %q (same args in different order)",
					syscall.Action,
					specs.ActAllow,
				)
			}

			if len(syscall.Args) != 2 {
				t.Errorf("clone args count = %d, want 2", len(syscall.Args))
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectArgsSameIndexReorderedFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		leftArgs  []specs.LinuxSeccompArg
		rightArgs []specs.LinuxSeccompArg
	}{
		{
			name: "different ValueTwo order",
			leftArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, ValueTwo: 20, Op: specs.OpMaskedEqual},
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpMaskedEqual},
			},
			rightArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpMaskedEqual},
				{Index: 0, Value: 1, ValueTwo: 20, Op: specs.OpMaskedEqual},
			},
		},
		{
			name: "different Op order",
			leftArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpNotEqual},
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpEqualTo},
			},
			rightArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpEqualTo},
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpNotEqual},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertReorderedArgsAllowed(t, testCase.leftArgs, testCase.rightArgs)
		})
	}
}

func assertReorderedArgsAllowed(
	t *testing.T,
	leftArgs, rightArgs []specs.LinuxSeccompArg,
) {
	t.Helper()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names: []string{syscallClone}, Action: specs.ActAllow, Args: leftArgs,
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names: []string{syscallClone}, Action: specs.ActAllow, Args: rightArgs,
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != len(leftArgs) {
				t.Errorf("clone args count = %d, want %d", len(syscall.Args), len(leftArgs))
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestUnionSyscallsDifferent(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActAllow}},
	)

	assertUnionSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActAllow,
		syscallWrite: specs.ActAllow,
	})
}

func TestUnionSyscallsLessRestrictive(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActErrno}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
	)

	assertUnionSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead: specs.ActAllow,
	})
}

func TestUnionSyscallsPreservesKillProcess(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActKillProcess}},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActAllow}},
	)

	assertUnionSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActKillProcess,
		syscallWrite: specs.ActAllow,
	})
}

func TestUnionSyscallsEmptyRight(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
		nil,
	)

	assertUnionSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActAllow,
		syscallWrite: specs.ActAllow,
	})
}

func TestUnionSyscallsNormalizesMultiName(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite, syscallOpen}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActLog}},
	)

	assertUnionSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActAllow,
		syscallWrite: specs.ActAllow,
		syscallOpen:  specs.ActAllow,
	})
}

func TestUnionSyscallsPreservesErrnoRet(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActErrno, ErrnoRet: uintPtr(42)},
		},
	)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	for _, syscall := range result {
		switch syscall.Names[0] {
		case syscallRead:
			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 13 {
				t.Errorf("read ErrnoRet = %v, want 13", syscall.ErrnoRet)
			}
		case syscallWrite:
			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 42 {
				t.Errorf("write ErrnoRet = %v, want 42", syscall.ErrnoRet)
			}
		}
	}
}

func TestUnionSyscallsSorted(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActAllow}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
	)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	if result[0].Names[0] != syscallRead || result[1].Names[0] != syscallWrite {
		t.Errorf("result not sorted: [%s, %s]", result[0].Names[0], result[1].Names[0])
	}
}

func assertUnionSyscallsResult(
	t *testing.T,
	result []specs.LinuxSyscall,
	want map[string]specs.LinuxSeccompAction,
) {
	t.Helper()

	got := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result {
		if len(syscall.Names) != 1 {
			t.Fatalf("expected single-name entry, got %v", syscall.Names)
		}

		got[syscall.Names[0]] = syscall.Action
	}

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}

	for name, wantAction := range want {
		if gotAction, ok := got[name]; !ok {
			t.Errorf("%s not found in result", name)
		} else if gotAction != wantAction {
			t.Errorf("%s action = %q, want %q", name, gotAction, wantAction)
		}
	}
}

func TestIntersectThreeProfiles(t *testing.T) {
	t.Parallel()

	first := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	second := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	third := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action := syscallMap[syscallRead]; action != specs.ActAllow {
		t.Errorf("read: got %q, want %q", action, specs.ActAllow)
	}

	if _, ok := syscallMap[syscallWrite]; ok {
		t.Error("write should not be in result (not allowed by profile c)")
	}

	if _, ok := syscallMap[syscallOpen]; ok {
		t.Error("open should not be in result (not allowed by profiles a and c)")
	}
}
