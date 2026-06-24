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

// Package landlock provides merge operations for Landlock profiles.
package landlock

import (
	"cmp"
	"fmt"
	"path"
	"slices"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = merge.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = merge.ErrNilProfile
)

// Intersect merges multiple Landlock profiles via intersection: the resulting
// profile restricts access to the intersection of what all input profiles
// allow. HandledAccessFS and HandledAccessNet are unioned (handling more rights
// makes the ruleset more restrictive overall, because unhandled rights are
// implicitly allowed). Path and network rules for entries present in both
// profiles have their access rights intersected. Entries present in only one
// profile are dropped if the corresponding access right is handled by the other
// profile, or kept as-is otherwise.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectStrategy{})
}

// Union merges multiple Landlock profiles via union: the resulting profile
// permits access if any input profile permits it. HandledAccessFS and
// HandledAccessNet are intersected (handling fewer rights makes the ruleset
// less restrictive, because unhandled rights are implicitly allowed). Path and
// network rules for entries present in both profiles have their access rights
// unioned. Entries present in only one profile are kept.
func Union(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, unionStrategy{})
}

type strategy interface {
	mergeHandledFS(left, right []FSAccessRight) []FSAccessRight
	mergeHandledNet(left, right []NetAccessRight) []NetAccessRight
	mergePathRules(left, right *Profile) []PathRule
	mergeNetRules(left, right *Profile) []NetRule
}

func foldProfiles(
	profiles []*Profile, mergeOp strategy,
) (*Profile, error) {
	for _, profile := range profiles {
		err := Validate(profile)
		if err != nil {
			return nil, fmt.Errorf("validate: %w", err)
		}
	}

	normalized := make([]*Profile, len(profiles))
	for idx, profile := range profiles {
		normalized[idx] = normalizeProfile(profile)
	}

	result, err := merge.Fold(normalized, cloneProfile, func(a, b *Profile) *Profile {
		return mergeTwo(a, b, mergeOp)
	})
	if err != nil {
		return nil, fmt.Errorf("fold: %w", err)
	}

	sortProfile(result)

	return result, nil
}

func sortProfile(profile *Profile) {
	slices.Sort(profile.HandledAccessFS)
	slices.Sort(profile.HandledAccessNet)

	slices.SortFunc(profile.PathRules, func(a, b PathRule) int {
		return cmp.Compare(a.Path, b.Path)
	})

	for idx := range profile.PathRules {
		slices.Sort(profile.PathRules[idx].AccessFS)
	}

	slices.SortFunc(profile.NetRules, func(a, b NetRule) int {
		return cmp.Compare(a.Port, b.Port)
	})

	for idx := range profile.NetRules {
		slices.Sort(profile.NetRules[idx].AccessNet)
	}
}

func mergeTwo(
	left, right *Profile, mergeStrategy strategy,
) *Profile {
	return &Profile{
		HandledAccessFS: mergeStrategy.mergeHandledFS(
			left.HandledAccessFS, right.HandledAccessFS,
		),
		HandledAccessNet: mergeStrategy.mergeHandledNet(
			left.HandledAccessNet, right.HandledAccessNet,
		),
		PathRules: mergeStrategy.mergePathRules(left, right),
		NetRules:  mergeStrategy.mergeNetRules(left, right),
	}
}

// intersectStrategy implements intersection semantics for Landlock profiles.
type intersectStrategy struct{}

func (intersectStrategy) mergeHandledFS(
	left, right []FSAccessRight,
) []FSAccessRight {
	return merge.UnionSlice(left, right)
}

func (intersectStrategy) mergeHandledNet(
	left, right []NetAccessRight,
) []NetAccessRight {
	return merge.UnionSlice(left, right)
}

func (intersectStrategy) mergePathRules(
	left, right *Profile,
) []PathRule {
	return intersectRules(
		left.PathRules, right.PathRules,
		right.HandledAccessFS, left.HandledAccessFS,
		pathRuleKey, pathRuleAccess,
		newPathRule, fsHandledSet, fsFilterUnhandled,
	)
}

func (intersectStrategy) mergeNetRules(
	left, right *Profile,
) []NetRule {
	return intersectRules(
		left.NetRules, right.NetRules,
		right.HandledAccessNet, left.HandledAccessNet,
		netRuleKey, netRuleAccess,
		newNetRule, netHandledSet, netFilterUnhandled,
	)
}

// intersectRules is a generic intersection for keyed rule slices.
// It avoids duplicating the path-rule and net-rule intersection logic.
func intersectRules[Rule any, Key comparable, Right comparable, Handled comparable](
	leftRules, rightRules []Rule,
	rightHandledRights, leftHandledRights []Handled,
	key func(Rule) Key,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
	handledSet func([]Handled) map[Handled]struct{},
	filterUnhandled func([]Right, map[Handled]struct{}) []Right,
) []Rule {
	leftMap := ruleMap(leftRules, key, access)
	rightMap := ruleMap(rightRules, key, access)

	rightHandled := handledSet(rightHandledRights)
	leftHandled := handledSet(leftHandledRights)

	result := make([]Rule, 0, len(leftRules)+len(rightRules))

	for ruleKey, leftAccess := range leftMap {
		if rightAccess, ok := rightMap[ruleKey]; ok {
			intersected := merge.IntersectSlice(leftAccess, rightAccess)
			if len(intersected) > 0 {
				result = append(result, build(ruleKey, intersected))
			}
		} else if filtered := filterUnhandled(
			leftAccess, rightHandled,
		); len(filtered) > 0 {
			result = append(result, build(ruleKey, filtered))
		}
	}

	for ruleKey, rightAccess := range rightMap {
		if _, ok := leftMap[ruleKey]; ok {
			continue
		}

		if filtered := filterUnhandled(
			rightAccess, leftHandled,
		); len(filtered) > 0 {
			result = append(result, build(ruleKey, filtered))
		}
	}

	return result
}

// unionStrategy implements union semantics for Landlock profiles.
type unionStrategy struct{}

func (unionStrategy) mergeHandledFS(
	left, right []FSAccessRight,
) []FSAccessRight {
	return merge.IntersectSlice(left, right)
}

func (unionStrategy) mergeHandledNet(
	left, right []NetAccessRight,
) []NetAccessRight {
	return merge.IntersectSlice(left, right)
}

func (unionStrategy) mergePathRules(
	left, right *Profile,
) []PathRule {
	return unionRules(
		left.PathRules, right.PathRules,
		pathRuleKey, pathRuleAccess, newPathRule,
	)
}

func (unionStrategy) mergeNetRules(
	left, right *Profile,
) []NetRule {
	return unionRules(
		left.NetRules, right.NetRules,
		netRuleKey, netRuleAccess, newNetRule,
	)
}

// unionRules is a generic union for keyed rule slices.
func unionRules[Rule any, Key comparable, Right comparable](
	leftRules, rightRules []Rule,
	key func(Rule) Key,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
) []Rule {
	leftMap := ruleMap(leftRules, key, access)
	rightMap := ruleMap(rightRules, key, access)

	result := make([]Rule, 0, len(leftRules)+len(rightRules))

	for ruleKey, leftAccess := range leftMap {
		if rightAccess, ok := rightMap[ruleKey]; ok {
			result = append(result, build(
				ruleKey, merge.UnionSlice(leftAccess, rightAccess),
			))
		} else {
			result = append(result, build(
				ruleKey, slices.Clone(leftAccess),
			))
		}
	}

	for ruleKey, rightAccess := range rightMap {
		if _, ok := leftMap[ruleKey]; ok {
			continue
		}

		result = append(result, build(
			ruleKey, slices.Clone(rightAccess),
		))
	}

	return result
}

// Rule accessor and builder functions for PathRule.

func pathRuleKey(rule PathRule) string             { return rule.Path }
func pathRuleAccess(rule PathRule) []FSAccessRight { return rule.AccessFS }

func newPathRule(rulePath string, access []FSAccessRight) PathRule {
	return PathRule{Path: rulePath, AccessFS: access}
}

// Rule accessor and builder functions for NetRule.

func netRuleKey(rule NetRule) uint16              { return rule.Port }
func netRuleAccess(rule NetRule) []NetAccessRight { return rule.AccessNet }

func newNetRule(port uint16, access []NetAccessRight) NetRule {
	return NetRule{Port: port, AccessNet: access}
}

// ruleMap builds a lookup map from key to access rights for any rule type.
func ruleMap[Rule any, Key comparable, Right comparable](
	rules []Rule,
	key func(Rule) Key,
	access func(Rule) []Right,
) map[Key][]Right {
	result := make(map[Key][]Right, len(rules))

	for _, rule := range rules {
		result[key(rule)] = access(rule)
	}

	return result
}

func fsHandledSet(
	rights []FSAccessRight,
) map[FSAccessRight]struct{} {
	return toSet(rights)
}

func netHandledSet(
	rights []NetAccessRight,
) map[NetAccessRight]struct{} {
	return toSet(rights)
}

func toSet[T comparable](items []T) map[T]struct{} {
	set := make(map[T]struct{}, len(items))

	for _, item := range items {
		set[item] = struct{}{}
	}

	return set
}

func fsFilterUnhandled(
	access []FSAccessRight, handled map[FSAccessRight]struct{},
) []FSAccessRight {
	return filterBySet(access, handled)
}

func netFilterUnhandled(
	access []NetAccessRight, handled map[NetAccessRight]struct{},
) []NetAccessRight {
	return filterBySet(access, handled)
}

func filterBySet[T comparable](
	items []T, exclude map[T]struct{},
) []T {
	var result []T

	for _, item := range items {
		if _, ok := exclude[item]; !ok {
			result = append(result, item)
		}
	}

	return result
}

func cloneProfile(profile *Profile) *Profile {
	return &Profile{
		HandledAccessFS:  slices.Clone(profile.HandledAccessFS),
		HandledAccessNet: slices.Clone(profile.HandledAccessNet),
		PathRules:        clonePathRules(profile.PathRules),
		NetRules:         cloneNetRules(profile.NetRules),
	}
}

func clonePathRules(rules []PathRule) []PathRule {
	if rules == nil {
		return nil
	}

	cloned := make([]PathRule, len(rules))

	for idx, rule := range rules {
		cloned[idx] = PathRule{
			Path:     rule.Path,
			AccessFS: slices.Clone(rule.AccessFS),
		}
	}

	return cloned
}

func normalizeProfile(profile *Profile) *Profile {
	clone := cloneProfile(profile)

	for idx := range clone.PathRules {
		clone.PathRules[idx].Path = path.Clean(clone.PathRules[idx].Path)
	}

	return clone
}

func cloneNetRules(rules []NetRule) []NetRule {
	if rules == nil {
		return nil
	}

	cloned := make([]NetRule, len(rules))

	for idx, rule := range rules {
		cloned[idx] = NetRule{
			Port:      rule.Port,
			AccessNet: slices.Clone(rule.AccessNet),
		}
	}

	return cloned
}
