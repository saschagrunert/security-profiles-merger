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
	"fmt"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

// ProfileDiff describes the differences between two seccomp profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles are identical.
	Equal bool `json:"equal"`

	// DefaultAction is set when the default actions differ.
	DefaultAction *ActionDiff `json:"defaultAction,omitempty"`

	// DefaultErrnoRet is set when the default errno return values differ.
	DefaultErrnoRet *UintPtrDiff `json:"defaultErrnoRet,omitempty"`

	// Architectures is set when the architecture lists differ.
	Architectures *SliceDiff[specs.Arch] `json:"architectures,omitempty"`

	// Flags is set when the flag lists differ.
	Flags *SliceDiff[specs.LinuxSeccompFlag] `json:"flags,omitempty"`

	// ListenerPath is set when the listener paths differ.
	ListenerPath *StringDiff `json:"listenerPath,omitempty"`

	// ListenerMetadata is set when the listener metadata differs.
	ListenerMetadata *StringDiff `json:"listenerMetadata,omitempty"`

	// Syscalls is set when the syscall entries differ.
	Syscalls *SyscallsDiff `json:"syscalls,omitempty"`
}

// ActionDiff represents a change in seccomp action.
type ActionDiff struct {
	Left  specs.LinuxSeccompAction `json:"left"`
	Right specs.LinuxSeccompAction `json:"right"`
}

// UintPtrDiff represents a change in an optional uint value.
type UintPtrDiff struct {
	Left  *uint `json:"left"`
	Right *uint `json:"right"`
}

// StringDiff represents a change in a string value.
type StringDiff struct {
	Left  string `json:"left"`
	Right string `json:"right"`
}

// SliceDiff represents added and removed items in a set-like slice.
type SliceDiff[T comparable] struct {
	Added   []T `json:"added,omitempty"`
	Removed []T `json:"removed,omitempty"`
}

// SyscallsDiff describes differences in the syscall entries.
type SyscallsDiff struct {
	Added   []SyscallEntry  `json:"added,omitempty"`
	Removed []SyscallEntry  `json:"removed,omitempty"`
	Changed []SyscallChange `json:"changed,omitempty"`
}

// SyscallEntry represents a single syscall with its action and arguments.
type SyscallEntry struct {
	Name     string                   `json:"name"`
	Action   specs.LinuxSeccompAction `json:"action"`
	ErrnoRet *uint                    `json:"errnoRet,omitempty"`
	Args     []specs.LinuxSeccompArg  `json:"args,omitempty"`
}

// SyscallChange represents a syscall present in both profiles with differences.
type SyscallChange struct {
	Name  string          `json:"name"`
	Left  []SyscallDetail `json:"left"`
	Right []SyscallDetail `json:"right"`
}

// SyscallDetail holds the action, errno, and args of a syscall entry.
type SyscallDetail struct {
	Action   specs.LinuxSeccompAction `json:"action"`
	ErrnoRet *uint                    `json:"errnoRet,omitempty"`
	Args     []specs.LinuxSeccompArg  `json:"args,omitempty"`
}

// Diff compares two seccomp profiles and returns a structured diff.
// Returns ErrNilProfile if either profile is nil.
func Diff(left, right *specs.LinuxSeccomp) (*ProfileDiff, error) {
	if left == nil || right == nil {
		return nil, ErrNilProfile
	}

	diff := &ProfileDiff{
		Equal:            true,
		DefaultAction:    nil,
		DefaultErrnoRet:  nil,
		Architectures:    nil,
		Flags:            nil,
		ListenerPath:     nil,
		ListenerMetadata: nil,
		Syscalls:         nil,
	}

	diffDefaultAction(diff, left, right)
	diffDefaultErrnoRet(diff, left, right)
	diffArchitectures(diff, left, right)
	diffFlags(diff, left, right)
	diffListener(diff, left, right)
	diffSyscallEntries(diff, left, right)

	return diff, nil
}

func diffDefaultAction(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	if left.DefaultAction != right.DefaultAction {
		diff.Equal = false
		diff.DefaultAction = &ActionDiff{
			Left:  left.DefaultAction,
			Right: right.DefaultAction,
		}
	}
}

func diffDefaultErrnoRet(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	if !equalUintPtr(left.DefaultErrnoRet, right.DefaultErrnoRet) {
		diff.Equal = false
		diff.DefaultErrnoRet = &UintPtrDiff{
			Left:  left.DefaultErrnoRet,
			Right: right.DefaultErrnoRet,
		}
	}
}

func equalUintPtr(first, second *uint) bool {
	if first == nil && second == nil {
		return true
	}

	if first == nil || second == nil {
		return false
	}

	return *first == *second
}

func diffArchitectures(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	result := diffSlice(left.Architectures, right.Architectures)
	if result != nil {
		diff.Equal = false
		diff.Architectures = result
	}
}

func diffFlags(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	result := diffSlice(left.Flags, right.Flags)
	if result != nil {
		diff.Equal = false
		diff.Flags = result
	}
}

func diffSlice[T cmp.Ordered](left, right []T) *SliceDiff[T] {
	leftSet := make(map[T]struct{}, len(left))
	for _, item := range left {
		leftSet[item] = struct{}{}
	}

	rightSet := make(map[T]struct{}, len(right))
	for _, item := range right {
		rightSet[item] = struct{}{}
	}

	var added, removed []T

	for item := range leftSet {
		if _, ok := rightSet[item]; !ok {
			removed = append(removed, item)
		}
	}

	for item := range rightSet {
		if _, ok := leftSet[item]; !ok {
			added = append(added, item)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return nil
	}

	slices.Sort(added)
	slices.Sort(removed)

	return &SliceDiff[T]{Added: added, Removed: removed}
}

func diffListener(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	if left.ListenerPath != right.ListenerPath {
		diff.Equal = false
		diff.ListenerPath = &StringDiff{
			Left:  left.ListenerPath,
			Right: right.ListenerPath,
		}
	}

	if left.ListenerMetadata != right.ListenerMetadata {
		diff.Equal = false
		diff.ListenerMetadata = &StringDiff{
			Left:  left.ListenerMetadata,
			Right: right.ListenerMetadata,
		}
	}
}

func diffSyscallEntries(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	leftMap := buildSyscallMap(left.Syscalls)
	rightMap := buildSyscallMap(right.Syscalls)

	var syscallsDiff SyscallsDiff

	leftNames := sortedKeys(leftMap)
	collectRemovedSyscalls(&syscallsDiff, leftNames, leftMap, rightMap)
	collectAddedSyscalls(&syscallsDiff, sortedKeys(rightMap), leftMap, rightMap)
	collectChangedSyscalls(&syscallsDiff, leftNames, leftMap, rightMap)

	if len(syscallsDiff.Added) > 0 ||
		len(syscallsDiff.Removed) > 0 ||
		len(syscallsDiff.Changed) > 0 {
		diff.Equal = false
		diff.Syscalls = &syscallsDiff
	}
}

func collectRemovedSyscalls(
	syscallsDiff *SyscallsDiff,
	names []string,
	leftMap, rightMap map[string][]SyscallEntry,
) {
	for _, name := range names {
		if _, ok := rightMap[name]; !ok {
			syscallsDiff.Removed = append(syscallsDiff.Removed, leftMap[name]...)
		}
	}
}

func collectAddedSyscalls(
	syscallsDiff *SyscallsDiff,
	names []string,
	leftMap, rightMap map[string][]SyscallEntry,
) {
	for _, name := range names {
		if _, ok := leftMap[name]; !ok {
			syscallsDiff.Added = append(syscallsDiff.Added, rightMap[name]...)
		}
	}
}

func collectChangedSyscalls(
	syscallsDiff *SyscallsDiff,
	names []string,
	leftMap, rightMap map[string][]SyscallEntry,
) {
	for _, name := range names {
		leftEntries := leftMap[name]

		rightEntries, ok := rightMap[name]
		if !ok {
			continue
		}

		if !equalSyscallEntrySlices(leftEntries, rightEntries) {
			syscallsDiff.Changed = append(syscallsDiff.Changed, SyscallChange{
				Name:  name,
				Left:  entriesToDetails(leftEntries),
				Right: entriesToDetails(rightEntries),
			})
		}
	}
}

func buildSyscallMap(
	syscalls []specs.LinuxSyscall,
) map[string][]SyscallEntry {
	result := make(map[string][]SyscallEntry)

	for _, syscall := range syscalls {
		for _, name := range syscall.Names {
			result[name] = append(result[name], SyscallEntry{
				Name:     name,
				Action:   syscall.Action,
				ErrnoRet: syscall.ErrnoRet,
				Args:     syscall.Args,
			})
		}
	}

	return result
}

func entriesToDetails(entries []SyscallEntry) []SyscallDetail {
	details := make([]SyscallDetail, 0, len(entries))

	for _, entry := range entries {
		details = append(details, SyscallDetail{
			Action:   entry.Action,
			ErrnoRet: entry.ErrnoRet,
			Args:     entry.Args,
		})
	}

	return details
}

func equalSyscallEntrySlices(left, right []SyscallEntry) bool {
	if len(left) != len(right) {
		return false
	}

	matched := make([]bool, len(right))

	for _, leftEntry := range left {
		found := false

		for rightIdx, rightEntry := range right {
			if !matched[rightIdx] && equalSyscallEntry(leftEntry, rightEntry) {
				matched[rightIdx] = true
				found = true

				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

func equalSyscallEntry(first, second SyscallEntry) bool {
	if first.Action != second.Action {
		return false
	}

	if !equalUintPtr(first.ErrnoRet, second.ErrnoRet) {
		return false
	}

	return slices.Equal(first.Args, second.Args)
}

func sortedKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}

// FormatDiff returns a human-readable representation of a seccomp profile diff.
func FormatDiff(diff *ProfileDiff) string {
	if diff == nil {
		return "Diff{<nil>}"
	}

	if diff.Equal {
		return "Diff{equal}"
	}

	var parts []string

	parts = appendScalarDiffs(parts, diff)
	parts = appendSliceDiffs(parts, diff)
	parts = appendListenerDiffs(parts, diff)

	if diff.Syscalls != nil {
		parts = append(parts, formatSyscallsDiff(diff.Syscalls)...)
	}

	return fmt.Sprintf("Diff{%s}", strings.Join(parts, " "))
}

func appendScalarDiffs(parts []string, diff *ProfileDiff) []string {
	if diff.DefaultAction != nil {
		parts = append(parts, fmt.Sprintf(
			"default:%s->%s",
			diff.DefaultAction.Left,
			diff.DefaultAction.Right,
		))
	}

	if diff.DefaultErrnoRet != nil {
		parts = append(parts, fmt.Sprintf(
			"defaultErrno:%s->%s",
			formatUintPtr(diff.DefaultErrnoRet.Left),
			formatUintPtr(diff.DefaultErrnoRet.Right),
		))
	}

	return parts
}

func appendSliceDiffs(parts []string, diff *ProfileDiff) []string {
	if diff.Architectures != nil {
		parts = append(parts, formatSliceDiff("arch", diff.Architectures))
	}

	if diff.Flags != nil {
		parts = append(parts, formatSliceDiff("flags", diff.Flags))
	}

	return parts
}

func appendListenerDiffs(parts []string, diff *ProfileDiff) []string {
	if diff.ListenerPath != nil {
		parts = append(parts, fmt.Sprintf(
			"listener:%s->%s",
			formatQuotedOrNone(diff.ListenerPath.Left),
			formatQuotedOrNone(diff.ListenerPath.Right),
		))
	}

	if diff.ListenerMetadata != nil {
		parts = append(parts, fmt.Sprintf(
			"listenerMeta:%s->%s",
			formatQuotedOrNone(diff.ListenerMetadata.Left),
			formatQuotedOrNone(diff.ListenerMetadata.Right),
		))
	}

	return parts
}

func formatUintPtr(val *uint) string {
	if val == nil {
		return "<nil>"
	}

	return strconv.FormatUint(uint64(*val), 10)
}

func formatQuotedOrNone(str string) string {
	if str == "" {
		return "<none>"
	}

	return str
}

func formatSliceDiff[T ~string](prefix string, sliceDiff *SliceDiff[T]) string {
	return merge.FormatDiffItems(prefix, sliceDiff.Removed, sliceDiff.Added)
}

func formatSyscallsDiff(syscallsDiff *SyscallsDiff) []string {
	parts := make([]string, 0,
		len(syscallsDiff.Removed)+len(syscallsDiff.Added)+len(syscallsDiff.Changed),
	)

	for _, entry := range syscallsDiff.Removed {
		parts = append(parts, "-"+entry.Name+"->"+string(entry.Action))
	}

	for _, entry := range syscallsDiff.Added {
		parts = append(parts, "+"+entry.Name+"->"+string(entry.Action))
	}

	for _, change := range syscallsDiff.Changed {
		parts = append(parts, fmt.Sprintf(
			"~%s:%s->%s",
			change.Name,
			formatDetailActions(change.Left),
			formatDetailActions(change.Right),
		))
	}

	return parts
}

func formatDetailActions(details []SyscallDetail) string {
	actions := make([]string, 0, len(details))

	for _, detail := range details {
		actions = append(actions, string(detail.Action))
	}

	return strings.Join(actions, ",")
}
