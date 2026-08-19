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

func allFuzzArchitectures() []specs.Arch {
	return []specs.Arch{
		specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
		specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
		specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
		specs.ArchPPC, specs.ArchPPC64, specs.ArchPPC64LE,
		specs.ArchS390, specs.ArchS390X,
		specs.ArchPARISC, specs.ArchPARISC64,
		specs.ArchRISCV64, specs.ArchLOONGARCH64,
		specs.ArchM68K, specs.ArchSH, specs.ArchSHEB,
	}
}

func allFuzzFlags() []specs.LinuxSeccompFlag {
	return []specs.LinuxSeccompFlag{
		specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv,
	}
}

func archsFromMask(mask uint32) []specs.Arch {
	archs := allFuzzArchitectures()

	var result []specs.Arch

	for idx, arch := range archs {
		if mask&(1<<idx) != 0 {
			result = append(result, arch)
		}
	}

	return result
}

func flagsFromMask(mask uint8) []specs.LinuxSeccompFlag {
	flags := allFuzzFlags()

	var result []specs.LinuxSeccompFlag

	for idx, flag := range flags {
		if mask&(1<<idx) != 0 {
			result = append(result, flag)
		}
	}

	return result
}

func fuzzProfile( //nolint:funlen // fuzz helper needs many parameters
	defaultIdx, action1Idx, action2Idx uint8,
	name1, name2 string,
	hasArgs1, hasArgs2 bool,
	argVal1, argVal2 uint64,
	archMask uint32,
	flagMask uint8,
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
		Architectures: archsFromMask(archMask),
		Flags:         flagsFromMask(flagMask),
		Syscalls:      []specs.LinuxSyscall{sc1, sc2},
	}
}

func addFuzzSeeds(f *testing.F) {
	f.Helper()

	// Baseline: ActAllow syscalls, one side with args, no archs/flags
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0), uint8(0),
		uint8(4), uint8(8), uint8(3),
		"read", "open", true, false, uint64(65536), uint64(0),
		uint32(0), uint8(0),
	)

	// Both sides have args on overlapping syscall
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"clone", "write", true, false, uint64(0x10000), uint64(0),
		uint32(0), uint8(0),
		uint8(4), uint8(8), uint8(8),
		"clone", "read", true, false, uint64(0x20000), uint64(0),
		uint32(0), uint8(0),
	)

	// Identical profiles with x86_64 arch and log flag
	f.Add(
		uint8(4), uint8(8), uint8(7),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x02), uint8(0x01),
		uint8(4), uint8(8), uint8(7),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x02), uint8(0x01),
	)

	// Disjoint syscall names with different architectures
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x01), uint8(0),
		uint8(4), uint8(8), uint8(8),
		"open", "close", false, false, uint64(0), uint64(0),
		uint32(0x02), uint8(0),
	)

	// Same syscall name in both profiles with different actions and flags
	f.Add(
		uint8(0), uint8(7), uint8(8),
		"mmap", "brk", true, false, uint64(0xFFFF), uint64(0),
		uint32(0x12), uint8(0x03),
		uint8(4), uint8(3), uint8(8),
		"mmap", "brk", true, false, uint64(0x1000), uint64(0),
		uint32(0x12), uint8(0x05),
	)

	// KillProcess default with overlapping architectures
	f.Add(
		uint8(0), uint8(5), uint8(6),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x13), uint8(0x07),
		uint8(0), uint8(6), uint8(5),
		"read", "open", false, false, uint64(0), uint64(0),
		uint32(0x12), uint8(0x03),
	)
}

type fuzzMergeConfig struct {
	merge       func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
	pickDefault func(specs.LinuxSeccompAction, specs.LinuxSeccompAction) specs.LinuxSeccompAction
}

func fuzzMerge( //nolint:funlen // fuzz helper needs many parameters
	t *testing.T,
	cfg fuzzMergeConfig,
	defL, act1L, act2L uint8,
	name1L, name2L string,
	args1L, args2L bool,
	argVal1L, argVal2L uint64,
	archMaskL uint32, flagMaskL uint8,
	defR, act1R, act2R uint8,
	name1R, name2R string,
	args1R, args2R bool,
	argVal1R, argVal2R uint64,
	archMaskR uint32, flagMaskR uint8,
) {
	t.Helper()

	left := fuzzProfile(
		defL, act1L, act2L, name1L, name2L,
		args1L, args2L, argVal1L, argVal2L,
		archMaskL, flagMaskL,
	)
	right := fuzzProfile(
		defR, act1R, act2R, name1R, name2R,
		args1R, args2R, argVal1R, argVal2R,
		archMaskR, flagMaskR,
	)

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

	if !equalModuloErrnoRet(idempotent, left) {
		t.Errorf(
			"Merge(X,X) should equal X modulo ErrnoRet\n  got:  %s\n  want: %s",
			seccomp.FormatProfile(idempotent),
			seccomp.FormatProfile(left),
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

	firstArchs := slices.Clone(first.Architectures)
	secondArchs := slices.Clone(second.Architectures)

	slices.Sort(firstArchs)
	slices.Sort(secondArchs)

	if !slices.Equal(firstArchs, secondArchs) {
		return false
	}

	firstFlags := slices.Clone(first.Flags)
	secondFlags := slices.Clone(second.Flags)

	slices.Sort(firstFlags)
	slices.Sort(secondFlags)

	if !slices.Equal(firstFlags, secondFlags) {
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
		archMaskL uint32, flagMaskL uint8,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
		archMaskR uint32, flagMaskR uint8,
	) {
		fuzzMerge(t, cfg,
			defL, act1L, act2L, name1L, name2L,
			args1L, args2L, argVal1L, argVal2L,
			archMaskL, flagMaskL,
			defR, act1R, act2R, name1R, name2R,
			args1R, args2R, argVal1R, argVal2R,
			archMaskR, flagMaskR,
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
		archMaskL uint32, flagMaskL uint8,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
		archMaskR uint32, flagMaskR uint8,
	) {
		fuzzMerge(t, cfg,
			defL, act1L, act2L, name1L, name2L,
			args1L, args2L, argVal1L, argVal2L,
			archMaskL, flagMaskL,
			defR, act1R, act2R, name1R, name2R,
			args1R, args2R, argVal1R, argVal2R,
			archMaskR, flagMaskR,
		)
	})
}

func FuzzDiff(f *testing.F) {
	addFuzzSeeds(f)

	f.Fuzz(func(
		t *testing.T,
		defL, act1L, act2L uint8,
		name1L, name2L string,
		args1L, args2L bool,
		argVal1L, argVal2L uint64,
		archMaskL uint32, flagMaskL uint8,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
		archMaskR uint32, flagMaskR uint8,
	) {
		left := fuzzProfile(
			defL, act1L, act2L, name1L, name2L,
			args1L, args2L, argVal1L, argVal2L,
			archMaskL, flagMaskL,
		)
		right := fuzzProfile(
			defR, act1R, act2R, name1R, name2R,
			args1R, args2R, argVal1R, argVal2R,
			archMaskR, flagMaskR,
		)

		diff, err := seccomp.Diff(left, right)
		if err != nil {
			t.Fatal(err)
		}

		seccomp.FormatDiff(diff)

		reverse, err := seccomp.Diff(right, left)
		if err != nil {
			t.Fatal(err)
		}

		if diff.Equal != reverse.Equal {
			t.Error("Diff(L,R).Equal != Diff(R,L).Equal")
		}

		assertSliceDiffSwapped(t, "Architectures", diff.Architectures, reverse.Architectures)
		assertSliceDiffSwapped(t, "Flags", diff.Flags, reverse.Flags)

		selfDiff, err := seccomp.Diff(left, left)
		if err != nil {
			t.Fatal(err)
		}

		if !selfDiff.Equal {
			t.Error("Diff(X, X) must be equal")
		}
	})
}

func FuzzValidateStrict(f *testing.F) { //nolint:funlen // fuzz seeds need many values
	f.Add(
		uint8(4),
		uint8(8),
		uint8(8),
		"read",
		"write",
		false,
		false,
		uint64(0),
		uint64(0),
		uint32(0),
		uint8(0),
	)
	f.Add(
		uint8(4),
		uint8(8),
		uint8(3),
		"read",
		"open",
		true,
		false,
		uint64(65536),
		uint64(0),
		uint32(0x02),
		uint8(0x01),
	)
	f.Add(
		uint8(0),
		uint8(7),
		uint8(8),
		"mmap",
		"brk",
		true,
		false,
		uint64(0xFFFF),
		uint64(0),
		uint32(0x13),
		uint8(0x07),
	)
	f.Add(
		uint8(0),
		uint8(5),
		uint8(6),
		"read",
		"write",
		false,
		false,
		uint64(0),
		uint64(0),
		uint32(0),
		uint8(0),
	)

	f.Fuzz(func(
		_ *testing.T,
		defIdx, act1Idx, act2Idx uint8,
		name1, name2 string,
		hasArgs1, hasArgs2 bool,
		argVal1, argVal2 uint64,
		archMask uint32, flagMask uint8,
	) {
		profile := fuzzProfile(
			defIdx, act1Idx, act2Idx,
			name1, name2, hasArgs1, hasArgs2,
			argVal1, argVal2,
			archMask, flagMask,
		)

		_ = seccomp.ValidateStrict(profile)
	})
}

func assertSliceDiffSwapped[T comparable](
	t *testing.T, label string,
	fwd, rev *seccomp.SliceDiff[T],
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Errorf("%s: nil mismatch", label)

		return
	}

	if fwd == nil {
		return
	}

	if !slices.Equal(fwd.Added, rev.Removed) {
		t.Errorf("%s: forward Added != reverse Removed", label)
	}

	if !slices.Equal(fwd.Removed, rev.Added) {
		t.Errorf("%s: forward Removed != reverse Added", label)
	}
}
