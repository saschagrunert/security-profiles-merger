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
		name1 = "read"
	}

	if name2 == "" {
		name2 = "write"
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
