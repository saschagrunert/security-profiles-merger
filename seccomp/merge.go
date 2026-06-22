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
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"

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
//
// This implements the profile merging semantics defined in KEP-6061 for CRI
// runtimes merging OCI-pulled profiles with node baselines.
func Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return merge(profiles, MoreRestrictive)
}

// Union merges multiple seccomp profiles via union: the resulting profile
// permits a syscall if any input profile permits it. For each syscall, the
// less restrictive action is chosen. Argument filters are combined.
//
// ListenerPath and ListenerMetadata are taken from the first profile.
//
// This implements the merge semantics used by the Security Profiles Operator
// for combining recorded profiles.
func Union(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return merge(profiles, LessRestrictive)
}

// actionPicker selects between two actions based on the merge strategy.
type actionPicker func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction

func merge(profiles []*specs.LinuxSeccomp, pick actionPicker) (*specs.LinuxSeccomp, error) {
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
		result = mergeTwo(result, profiles[idx], pick)
	}

	return result, nil
}

func mergeTwo(
	left, right *specs.LinuxSeccomp,
	pick actionPicker,
) *specs.LinuxSeccomp {
	return &specs.LinuxSeccomp{
		DefaultAction: pick(left.DefaultAction, right.DefaultAction),
		DefaultErrnoRet: mergeErrnoRet(
			left.DefaultErrnoRet,
			right.DefaultErrnoRet,
			left.DefaultAction,
			right.DefaultAction,
			pick,
		),
		Architectures:    mergeArchitectures(left.Architectures, right.Architectures, pick),
		Flags:            mergeFlags(left.Flags, right.Flags, pick),
		Syscalls:         mergeSyscalls(left, right, pick),
		ListenerPath:     left.ListenerPath,
		ListenerMetadata: left.ListenerMetadata,
	}
}

func normalizeSyscalls(
	profile *specs.LinuxSeccomp,
	pick actionPicker,
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
				normalized[name] = pickSyscall(existing, entry, pick)
			} else {
				normalized[name] = entry
			}
		}
	}

	return normalized
}

func mergeSyscalls(
	left, right *specs.LinuxSeccomp,
	pick actionPicker,
) []specs.LinuxSyscall {
	leftMap := normalizeSyscalls(left, pick)
	rightMap := normalizeSyscalls(right, pick)

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
			mergedDefault, pick,
		)
		if entry != nil {
			result = append(result, *entry)
		}
	}

	sort.Slice(result, func(idx, jdx int) bool {
		return result[idx].Names[0] < result[jdx].Names[0]
	})

	return result
}

func mergeSyscallEntry(
	leftEntry, rightEntry *specs.LinuxSyscall,
	leftDefault, rightDefault, mergedDefault specs.LinuxSeccompAction,
	pick actionPicker,
) *specs.LinuxSyscall {
	switch {
	case leftEntry != nil && rightEntry != nil:
		return mergeMatchedSyscall(leftEntry, rightEntry, mergedDefault, pick)
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
	pick actionPicker,
) *specs.LinuxSyscall {
	merged := pickSyscall(left, right, pick)
	if merged.Action != mergedDefault || len(merged.Args) > 0 {
		return merged
	}

	return nil
}

func mergeUnmatchedSyscall(
	entry *specs.LinuxSyscall,
	otherDefault, mergedDefault specs.LinuxSeccompAction,
	pick actionPicker,
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
	pick actionPicker,
) *specs.LinuxSyscall {
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

	args, denied := mergeArgs(left.Args, right.Args, pick)
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
	pick actionPicker,
) ([]specs.LinuxSeccompArg, bool) {
	if pick(specs.ActAllow, specs.ActErrno) == specs.ActErrno {
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

	if reflect.DeepEqual(leftArgs, rightArgs) {
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

	if reflect.DeepEqual(leftArgs, rightArgs) {
		return slices.Clone(leftArgs), false
	}

	combined := make([]specs.LinuxSeccompArg, 0, len(leftArgs)+len(rightArgs))
	combined = append(combined, leftArgs...)

	for _, rightArg := range rightArgs {
		found := false

		for _, leftArg := range leftArgs {
			if reflect.DeepEqual(leftArg, rightArg) {
				found = true

				break
			}
		}

		if !found {
			combined = append(combined, rightArg)
		}
	}

	return combined, false
}

func mergeErrnoRet(
	leftRet, rightRet *uint,
	leftAction, rightAction specs.LinuxSeccompAction,
	pick actionPicker,
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

func mergeArchitectures(
	left, right []specs.Arch,
	pick actionPicker,
) []specs.Arch {
	if pick(specs.ActAllow, specs.ActErrno) == specs.ActErrno {
		return intersectArchitectures(left, right)
	}

	return unionArchitectures(left, right)
}

func intersectArchitectures(left, right []specs.Arch) []specs.Arch {
	if len(left) == 0 {
		return slices.Clone(right)
	}

	if len(right) == 0 {
		return slices.Clone(left)
	}

	rightSet := make(map[specs.Arch]struct{}, len(right))
	for _, arch := range right {
		rightSet[arch] = struct{}{}
	}

	var result []specs.Arch

	for _, arch := range left {
		if _, ok := rightSet[arch]; ok {
			result = append(result, arch)
		}
	}

	return result
}

func unionArchitectures(left, right []specs.Arch) []specs.Arch {
	seen := make(map[specs.Arch]struct{})

	var result []specs.Arch

	for _, arch := range left {
		if _, ok := seen[arch]; !ok {
			seen[arch] = struct{}{}
			result = append(result, arch)
		}
	}

	for _, arch := range right {
		if _, ok := seen[arch]; !ok {
			seen[arch] = struct{}{}
			result = append(result, arch)
		}
	}

	return result
}

func mergeFlags(
	left, right []specs.LinuxSeccompFlag,
	pick actionPicker,
) []specs.LinuxSeccompFlag {
	if pick(specs.ActAllow, specs.ActErrno) == specs.ActErrno {
		return intersectFlags(left, right)
	}

	return unionFlags(left, right)
}

func intersectFlags(left, right []specs.LinuxSeccompFlag) []specs.LinuxSeccompFlag {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}

	rightSet := make(map[specs.LinuxSeccompFlag]struct{}, len(right))
	for _, flag := range right {
		rightSet[flag] = struct{}{}
	}

	var result []specs.LinuxSeccompFlag

	for _, flag := range left {
		if _, ok := rightSet[flag]; ok {
			result = append(result, flag)
		}
	}

	return result
}

func unionFlags(left, right []specs.LinuxSeccompFlag) []specs.LinuxSeccompFlag {
	seen := make(map[specs.LinuxSeccompFlag]struct{})

	var result []specs.LinuxSeccompFlag

	for _, flag := range left {
		if _, ok := seen[flag]; !ok {
			seen[flag] = struct{}{}
			result = append(result, flag)
		}
	}

	for _, flag := range right {
		if _, ok := seen[flag]; !ok {
			seen[flag] = struct{}{}
			result = append(result, flag)
		}
	}

	return result
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
