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

package seccomp

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = errors.New("at least one profile is required")
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = errors.New("profile must not be nil")
)

// Intersect merges multiple seccomp profiles via intersection: the resulting
// profile permits a syscall only if all input profiles permit it. For each
// syscall, the more restrictive action is chosen. When argument filters differ
// and the intersection cannot be computed precisely, the syscall is denied
// (conservative).
//
// ListenerPath and ListenerMetadata are taken from the first profile.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
//
// An empty Architectures list is treated as "unspecified" and defers to the
// other profile. Per the OCI runtime-spec, empty means "native architecture
// only", but the native architecture is unknown at merge time. Callers that
// need precise architecture intersection should populate the native
// architecture explicitly before merging.
//
// This implements the profile merging semantics defined in KEP-6061 for CRI
// runtimes merging OCI-pulled profiles with node baselines.
func Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return merge(profiles, mergeStrategy{pick: MoreRestrictive, isIntersect: true})
}

// Union merges multiple seccomp profiles via union: the resulting profile
// permits a syscall if any input profile permits it. For each syscall, the
// less restrictive action is chosen. Argument filters are combined.
//
// ListenerPath and ListenerMetadata are taken from the first profile.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
//
// This implements the merge semantics used by the Security Profiles Operator
// for combining recorded profiles.
func Union(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return merge(profiles, mergeStrategy{pick: LessRestrictive, isIntersect: false})
}

type mergeStrategy struct {
	pick        func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction
	isIntersect bool
}

func merge(profiles []*specs.LinuxSeccomp, strategy mergeStrategy) (*specs.LinuxSeccomp, error) {
	if len(profiles) == 0 {
		return nil, ErrNoProfiles
	}

	for idx, profile := range profiles {
		if profile == nil {
			return nil, fmt.Errorf("profile at index %d: %w", idx, ErrNilProfile)
		}
	}

	result := cloneProfile(profiles[0])

	for idx := 1; idx < len(profiles); idx++ {
		result = mergeTwo(result, profiles[idx], strategy)
	}

	return result, nil
}

func mergeTwo(
	left, right *specs.LinuxSeccomp,
	strategy mergeStrategy,
) *specs.LinuxSeccomp {
	pick := strategy.pick

	merged := &specs.LinuxSeccomp{
		DefaultAction: pick(left.DefaultAction, right.DefaultAction),
		DefaultErrnoRet: mergeErrnoRet(
			left.DefaultErrnoRet,
			right.DefaultErrnoRet,
			left.DefaultAction,
			right.DefaultAction,
			pick,
		),
		Syscalls:         mergeSyscalls(left, right, strategy),
		ListenerPath:     left.ListenerPath,
		ListenerMetadata: left.ListenerMetadata,
	}

	if strategy.isIntersect {
		merged.Architectures = intersectArchitectures(left.Architectures, right.Architectures)
		merged.Flags = intersectSlice(left.Flags, right.Flags)
	} else {
		merged.Architectures = unionSlice(left.Architectures, right.Architectures)
		merged.Flags = unionSlice(left.Flags, right.Flags)
	}

	return merged
}

func intersectSlice[T comparable](left, right []T) []T {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}

	rightSet := make(map[T]struct{}, len(right))
	for _, val := range right {
		rightSet[val] = struct{}{}
	}

	var result []T

	for _, val := range left {
		if _, ok := rightSet[val]; ok {
			result = append(result, val)
		}
	}

	return result
}

func unionSlice[T comparable](left, right []T) []T {
	seen := make(map[T]struct{})

	var result []T

	for _, val := range left {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	for _, val := range right {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	return result
}

func intersectArchitectures(left, right []specs.Arch) []specs.Arch {
	if len(left) == 0 {
		return slices.Clone(right)
	}

	if len(right) == 0 {
		return slices.Clone(left)
	}

	return intersectSlice(left, right)
}

func normalizeSyscalls(
	profile *specs.LinuxSeccomp,
	strategy mergeStrategy,
) map[string]*specs.LinuxSyscall {
	normalized := make(map[string]*specs.LinuxSyscall)

	for idx := range profile.Syscalls {
		syscall := &profile.Syscalls[idx]

		for _, name := range syscall.Names {
			entry := &specs.LinuxSyscall{
				Names:    []string{name},
				Action:   syscall.Action,
				ErrnoRet: syscall.ErrnoRet,
				Args:     syscall.Args,
			}

			if existing, ok := normalized[name]; ok {
				normalized[name] = pickSyscall(existing, entry, strategy)
			} else {
				normalized[name] = entry
			}
		}
	}

	return normalized
}

func mergeSyscalls(
	left, right *specs.LinuxSeccomp,
	strategy mergeStrategy,
) []specs.LinuxSyscall {
	pick := strategy.pick
	leftMap := normalizeSyscalls(left, strategy)
	rightMap := normalizeSyscalls(right, strategy)

	allNames := make(map[string]struct{})
	for name := range leftMap {
		allNames[name] = struct{}{}
	}

	for name := range rightMap {
		allNames[name] = struct{}{}
	}

	mergedDefault := pick(left.DefaultAction, right.DefaultAction)

	var result []specs.LinuxSyscall

	for name := range allNames {
		entry := mergeSyscallEntry(
			leftMap[name], rightMap[name],
			left.DefaultAction, right.DefaultAction,
			mergedDefault, strategy,
		)
		if entry != nil {
			result = append(result, *entry)
		}
	}

	slices.SortFunc(result, func(a, b specs.LinuxSyscall) int {
		return cmp.Compare(a.Names[0], b.Names[0])
	})

	return result
}

func mergeSyscallEntry(
	leftEntry, rightEntry *specs.LinuxSyscall,
	leftDefault, rightDefault, mergedDefault specs.LinuxSeccompAction,
	strategy mergeStrategy,
) *specs.LinuxSyscall {
	pick := strategy.pick

	switch {
	case leftEntry != nil && rightEntry != nil:
		return mergeMatchedSyscall(leftEntry, rightEntry, mergedDefault, strategy)
	case leftEntry != nil:
		return mergeUnmatchedSyscall(leftEntry, rightDefault, mergedDefault, pick)
	case rightEntry != nil:
		return mergeUnmatchedSyscall(rightEntry, leftDefault, mergedDefault, pick)
	}

	return nil
}

func mergeMatchedSyscall(
	left, right *specs.LinuxSyscall,
	mergedDefault specs.LinuxSeccompAction,
	strategy mergeStrategy,
) *specs.LinuxSyscall {
	merged := pickSyscall(left, right, strategy)
	if merged.Action != mergedDefault || len(merged.Args) > 0 {
		return merged
	}

	return nil
}

func mergeUnmatchedSyscall(
	entry *specs.LinuxSyscall,
	otherDefault, mergedDefault specs.LinuxSeccompAction,
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction,
) *specs.LinuxSyscall {
	effective := pick(entry.Action, otherDefault)
	if effective != mergedDefault || len(entry.Args) > 0 {
		return &specs.LinuxSyscall{
			Names:    slices.Clone(entry.Names),
			Action:   effective,
			ErrnoRet: copyErrnoRet(entry.ErrnoRet),
			Args:     slices.Clone(entry.Args),
		}
	}

	return nil
}

func pickSyscall(
	left, right *specs.LinuxSyscall,
	strategy mergeStrategy,
) *specs.LinuxSyscall {
	pick := strategy.pick
	pickedAction := pick(left.Action, right.Action)

	result := &specs.LinuxSyscall{
		Names:  left.Names,
		Action: pickedAction,
	}

	if pickedAction == left.Action {
		result.ErrnoRet = copyErrnoRet(left.ErrnoRet)
	} else {
		result.ErrnoRet = copyErrnoRet(right.ErrnoRet)
	}

	args, denied := mergeArgs(left.Args, right.Args, strategy.isIntersect)
	if denied {
		result.Action = specs.ActKillProcess
		result.ErrnoRet = nil
		result.Args = nil
	} else {
		result.Args = args
	}

	return result
}

func mergeArgs(
	leftArgs, rightArgs []specs.LinuxSeccompArg,
	isIntersect bool,
) ([]specs.LinuxSeccompArg, bool) {
	if isIntersect {
		return intersectArgs(leftArgs, rightArgs)
	}

	return unionArgs(leftArgs, rightArgs)
}

func intersectArgs(
	leftArgs, rightArgs []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	if len(leftArgs) == 0 && len(rightArgs) == 0 {
		return nil, false
	}

	if len(leftArgs) == 0 {
		return slices.Clone(rightArgs), false
	}

	if len(rightArgs) == 0 {
		return slices.Clone(leftArgs), false
	}

	if slices.Equal(leftArgs, rightArgs) {
		return slices.Clone(leftArgs), false
	}

	return nil, true
}

func unionArgs(
	leftArgs, rightArgs []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	if len(leftArgs) == 0 && len(rightArgs) == 0 {
		return nil, false
	}

	if len(leftArgs) == 0 || len(rightArgs) == 0 {
		return nil, false
	}

	combined := make([]specs.LinuxSeccompArg, 0, len(leftArgs)+len(rightArgs))
	combined = append(combined, leftArgs...)

	for _, rightArg := range rightArgs {
		if !slices.Contains(leftArgs, rightArg) {
			combined = append(combined, rightArg)
		}
	}

	return combined, false
}

func mergeErrnoRet(
	leftRet, rightRet *uint,
	leftAction, rightAction specs.LinuxSeccompAction,
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction,
) *uint {
	picked := pick(leftAction, rightAction)

	if picked == leftAction && leftRet != nil {
		ret := *leftRet

		return &ret
	}

	if picked == rightAction && rightRet != nil {
		ret := *rightRet

		return &ret
	}

	return nil
}

func cloneProfile(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	clone := &specs.LinuxSeccomp{
		DefaultAction:    profile.DefaultAction,
		ListenerPath:     profile.ListenerPath,
		ListenerMetadata: profile.ListenerMetadata,
	}

	if profile.DefaultErrnoRet != nil {
		ret := *profile.DefaultErrnoRet
		clone.DefaultErrnoRet = &ret
	}

	clone.Architectures = slices.Clone(profile.Architectures)
	clone.Flags = slices.Clone(profile.Flags)
	clone.Syscalls = make([]specs.LinuxSyscall, len(profile.Syscalls))

	for idx, syscall := range profile.Syscalls {
		clone.Syscalls[idx] = specs.LinuxSyscall{
			Names:  slices.Clone(syscall.Names),
			Action: syscall.Action,
			Args:   slices.Clone(syscall.Args),
		}

		if syscall.ErrnoRet != nil {
			ret := *syscall.ErrnoRet
			clone.Syscalls[idx].ErrnoRet = &ret
		}
	}

	return clone
}

func copyErrnoRet(ret *uint) *uint {
	if ret == nil {
		return nil
	}

	val := *ret

	return &val
}
