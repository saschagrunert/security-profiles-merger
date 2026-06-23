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
	"cmp"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

func fuzzProfile(
	defaultIdx, action1Idx, action2Idx uint8,
	name1, name2 string,
	hasArgs1, hasArgs2 bool,
	argVal1, argVal2 uint64,
) *specs.LinuxSeccomp {
	actions := []specs.LinuxSeccompAction{
		specs.ActKillProcess,
		specs.ActKillThread,
		specs.ActKill,
		specs.ActTrap,
		specs.ActErrno,
		specs.ActTrace,
		specs.ActNotify,
		specs.ActLog,
		specs.ActAllow,
	}

	defaultAction := actions[int(defaultIdx)%len(actions)]
	act1 := actions[int(action1Idx)%len(actions)]
	act2 := actions[int(action2Idx)%len(actions)]

	if name1 == "" {
		name1 = syscallRead
	}

	if name2 == "" {
		name2 = syscallWrite
	}

	if name2 == name1 {
		name2 = name1 + "_alt"
	}

	sc1 := specs.LinuxSyscall{
		Names:  []string{name1},
		Action: act1,
	}

	if hasArgs1 {
		sc1.Args = []specs.LinuxSeccompArg{
			{Index: 0, Value: argVal1, Op: specs.OpEqualTo},
		}
	}

	sc2 := specs.LinuxSyscall{
		Names:  []string{name2},
		Action: act2,
	}

	if hasArgs2 {
		sc2.Args = []specs.LinuxSeccompArg{
			{Index: 0, Value: argVal2, Op: specs.OpEqualTo},
		}
	}

	return &specs.LinuxSeccomp{
		DefaultAction: defaultAction,
		Syscalls:      []specs.LinuxSyscall{sc1, sc2},
	}
}

func addFuzzSeeds(f *testing.F) {
	f.Helper()

	// Baseline: ActAllow syscalls, one side with args
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint8(4), uint8(8), uint8(3),
		"read", "open", true, false, uint64(65536), uint64(0),
	)

	// Both sides have args on overlapping syscall
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"clone", "write", true, false, uint64(0x10000), uint64(0),
		uint8(4), uint8(8), uint8(8),
		"clone", "read", true, false, uint64(0x20000), uint64(0),
	)

	// Identical profiles
	f.Add(
		uint8(4), uint8(8), uint8(7),
		"read", "write", false, false, uint64(0), uint64(0),
		uint8(4), uint8(8), uint8(7),
		"read", "write", false, false, uint64(0), uint64(0),
	)

	// Disjoint syscall names
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint8(4), uint8(8), uint8(8),
		"open", "close", false, false, uint64(0), uint64(0),
	)

	// Same syscall name in both profiles with different actions
	f.Add(
		uint8(0), uint8(7), uint8(8),
		"mmap", "brk", true, false, uint64(0xFFFF), uint64(0),
		uint8(4), uint8(3), uint8(8),
		"mmap", "brk", true, false, uint64(0x1000), uint64(0),
	)

	// KillProcess default with Log/Notify syscalls
	f.Add(
		uint8(0), uint8(5), uint8(6),
		"read", "write", false, false, uint64(0), uint64(0),
		uint8(0), uint8(6), uint8(5),
		"read", "open", false, false, uint64(0), uint64(0),
	)
}

type fuzzMergeConfig struct {
	merge       func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
	pickDefault func(specs.LinuxSeccompAction, specs.LinuxSeccompAction) specs.LinuxSeccompAction
}

func fuzzMerge(
	t *testing.T,
	cfg fuzzMergeConfig,
	defL, act1L, act2L uint8,
	name1L, name2L string,
	args1L, args2L bool,
	argVal1L, argVal2L uint64,
	defR, act1R, act2R uint8,
	name1R, name2R string,
	args1R, args2R bool,
	argVal1R, argVal2R uint64,
) {
	t.Helper()

	left := fuzzProfile(defL, act1L, act2L, name1L, name2L, args1L, args2L, argVal1L, argVal2L)
	right := fuzzProfile(defR, act1R, act2R, name1R, name2R, args1R, args2R, argVal1R, argVal2R)

	result, err := cfg.merge(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if result == nil {
		t.Fatal("result must not be nil")
	}

	expectedDefault := cfg.pickDefault(left.DefaultAction, right.DefaultAction)
	if result.DefaultAction != expectedDefault {
		t.Errorf(
			"default = %q, want %q (pick of %q and %q)",
			result.DefaultAction, expectedDefault,
			left.DefaultAction, right.DefaultAction,
		)
	}

	commuted, err := cfg.merge(right, left)
	if err != nil {
		t.Fatalf("commuted merge: %v", err)
	}

	if !equalModuloErrnoRet(result, commuted) {
		t.Error("Merge(L,R) != Merge(R,L) modulo ErrnoRet")
	}

	idempotent, err := cfg.merge(left, left)
	if err != nil {
		t.Fatalf("idempotent merge: %v", err)
	}

	if idempotent.DefaultAction != left.DefaultAction {
		t.Errorf(
			"idempotent default = %q, want %q",
			idempotent.DefaultAction, left.DefaultAction,
		)
	}
}

func sameRestrictiveness(
	actionA, actionB specs.LinuxSeccompAction,
) bool {
	return seccomp.MoreRestrictive(actionA, actionB) == actionA &&
		seccomp.MoreRestrictive(actionB, actionA) == actionB
}

func filterRedundantSyscalls(
	syscalls []specs.LinuxSyscall,
	defaultAction specs.LinuxSeccompAction,
) []specs.LinuxSyscall {
	result := make([]specs.LinuxSyscall, 0, len(syscalls))

	for _, sc := range syscalls {
		if len(sc.Args) == 0 && sameRestrictiveness(sc.Action, defaultAction) {
			continue
		}

		result = append(result, sc)
	}

	return result
}

func equalModuloErrnoRet(
	first, second *specs.LinuxSeccomp,
) bool {
	if !sameRestrictiveness(first.DefaultAction, second.DefaultAction) {
		return false
	}

	if !slices.Equal(first.Architectures, second.Architectures) {
		return false
	}

	if !slices.Equal(first.Flags, second.Flags) {
		return false
	}

	firstSyscalls := filterRedundantSyscalls(first.Syscalls, first.DefaultAction)
	secondSyscalls := filterRedundantSyscalls(second.Syscalls, second.DefaultAction)

	if len(firstSyscalls) != len(secondSyscalls) {
		return false
	}

	sortSyscallsByName(firstSyscalls)
	sortSyscallsByName(secondSyscalls)

	for idx := range firstSyscalls {
		if firstSyscalls[idx].Names[0] != secondSyscalls[idx].Names[0] {
			return false
		}

		if !sameRestrictiveness(firstSyscalls[idx].Action, secondSyscalls[idx].Action) {
			return false
		}

		if !equalArgsSorted(firstSyscalls[idx].Args, secondSyscalls[idx].Args) {
			return false
		}
	}

	return true
}

func sortSyscallsByName(syscalls []specs.LinuxSyscall) {
	slices.SortFunc(syscalls, func(left, right specs.LinuxSyscall) int {
		return cmp.Compare(left.Names[0], right.Names[0])
	})
}

func equalArgsSorted(
	first, second []specs.LinuxSeccompArg,
) bool {
	firstClone := slices.Clone(first)
	secondClone := slices.Clone(second)

	sortArgsByValue(firstClone)
	sortArgsByValue(secondClone)

	return slices.Equal(firstClone, secondClone)
}

func sortArgsByValue(args []specs.LinuxSeccompArg) {
	slices.SortFunc(args, func(left, right specs.LinuxSeccompArg) int {
		if result := cmp.Compare(left.Index, right.Index); result != 0 {
			return result
		}

		if result := cmp.Compare(left.Value, right.Value); result != 0 {
			return result
		}

		if result := cmp.Compare(left.ValueTwo, right.ValueTwo); result != 0 {
			return result
		}

		return cmp.Compare(string(left.Op), string(right.Op))
	})
}

func FuzzIntersect(f *testing.F) {
	addFuzzSeeds(f)

	cfg := fuzzMergeConfig{merge: seccomp.Intersect, pickDefault: seccomp.MoreRestrictive}

	f.Fuzz(func(
		t *testing.T,
		defL, act1L, act2L uint8,
		name1L, name2L string,
		args1L, args2L bool,
		argVal1L, argVal2L uint64,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
	) {
		fuzzMerge(t, cfg,
			defL, act1L, act2L, name1L, name2L, args1L, args2L, argVal1L, argVal2L,
			defR, act1R, act2R, name1R, name2R, args1R, args2R, argVal1R, argVal2R,
		)
	})
}

func FuzzUnion(f *testing.F) {
	addFuzzSeeds(f)

	cfg := fuzzMergeConfig{merge: seccomp.Union, pickDefault: seccomp.LessRestrictive}

	f.Fuzz(func(
		t *testing.T,
		defL, act1L, act2L uint8,
		name1L, name2L string,
		args1L, args2L bool,
		argVal1L, argVal2L uint64,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
	) {
		fuzzMerge(t, cfg,
			defL, act1L, act2L, name1L, name2L, args1L, args2L, argVal1L, argVal2L,
			defR, act1R, act2R, name1R, name2R, args1R, args2R, argVal1R, argVal2R,
		)
	})
}
