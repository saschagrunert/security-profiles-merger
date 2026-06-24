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

package landlock_test

import (
	"cmp"
	"path/filepath"
	"slices"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/landlock"
)

func allFSRightsForFuzz() []landlock.FSAccessRight {
	return []landlock.FSAccessRight{
		landlock.FSAccessExecute,
		landlock.FSAccessWriteFile,
		landlock.FSAccessReadFile,
		landlock.FSAccessReadDir,
		landlock.FSAccessRemoveDir,
		landlock.FSAccessRemoveFile,
		landlock.FSAccessMakeChar,
		landlock.FSAccessMakeDir,
		landlock.FSAccessMakeReg,
		landlock.FSAccessMakeSock,
		landlock.FSAccessMakeFIFO,
		landlock.FSAccessMakeSym,
		landlock.FSAccessMakeBlock,
		landlock.FSAccessRefer,
		landlock.FSAccessTruncate,
		landlock.FSAccessIOCTLDev,
		landlock.FSAccessResolveUnix,
	}
}

func allNetRightsForFuzz() []landlock.NetAccessRight {
	return []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
		landlock.NetAccessBindUDP,
		landlock.NetAccessConnectSendUDP,
	}
}

func fuzzLandlockProfile(
	handledFSMask uint32, handledNetMask uint8,
	path1, path2 string,
	accessMask1, accessMask2 uint32,
	port1, port2 uint16,
	netMask1, netMask2 uint8,
) *landlock.Profile {
	handledFS := pickFSRights(handledFSMask)
	handledNet := pickNetRights(handledNetMask)

	if path1 == "" {
		path1 = "/default1"
	}

	if path2 == "" {
		path2 = "/default2"
	}

	path1 = filepath.Clean(path1)
	path2 = filepath.Clean(path2)

	pathRules := buildFuzzPathRules(
		path1, path2,
		accessMask1&handledFSMask, accessMask2&handledFSMask,
	)
	netRules := buildFuzzNetRules(
		port1, port2, netMask1&handledNetMask, netMask2&handledNetMask,
	)

	return &landlock.Profile{
		HandledAccessFS:  handledFS,
		HandledAccessNet: handledNet,
		PathRules:        pathRules,
		NetRules:         netRules,
	}
}

func buildFuzzPathRules(
	path1, path2 string,
	accessMask1, accessMask2 uint32,
) []landlock.PathRule {
	var pathRules []landlock.PathRule

	if access := pickFSRights(accessMask1); len(access) > 0 {
		pathRules = append(pathRules, landlock.PathRule{
			Path:     path1,
			AccessFS: access,
		})
	}

	if path2 != path1 {
		if access := pickFSRights(accessMask2); len(access) > 0 {
			pathRules = append(pathRules, landlock.PathRule{
				Path:     path2,
				AccessFS: access,
			})
		}
	}

	return pathRules
}

func buildFuzzNetRules(
	port1, port2 uint16,
	netMask1, netMask2 uint8,
) []landlock.NetRule {
	var netRules []landlock.NetRule

	if access := pickNetRights(netMask1); len(access) > 0 {
		netRules = append(netRules, landlock.NetRule{
			Port:      port1,
			AccessNet: access,
		})
	}

	if port2 != port1 {
		if access := pickNetRights(netMask2); len(access) > 0 {
			netRules = append(netRules, landlock.NetRule{
				Port:      port2,
				AccessNet: access,
			})
		}
	}

	return netRules
}

func pickFSRights(mask uint32) []landlock.FSAccessRight {
	all := allFSRightsForFuzz()

	var rights []landlock.FSAccessRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func pickNetRights(mask uint8) []landlock.NetAccessRight {
	all := allNetRightsForFuzz()

	var rights []landlock.NetAccessRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func addLandlockFuzzSeeds(f *testing.F) {
	f.Helper()

	// Baseline: overlapping paths.
	f.Add(
		uint32(0x07), uint8(0x03),
		"/etc", "/home",
		uint32(0x05), uint32(0x03),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x07), uint8(0x03),
		"/etc", "/tmp",
		uint32(0x01), uint32(0x06),
		uint16(80), uint16(8080),
		uint8(0x03), uint8(0x01),
	)

	// Identical profiles.
	f.Add(
		uint32(0x03), uint8(0x01),
		"/etc", "/home",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x03), uint8(0x01),
		"/etc", "/home",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)

	// Disjoint paths.
	f.Add(
		uint32(0x1FFFF), uint8(0x0F),
		"/a", "/b",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x1FFFF), uint8(0x0F),
		"/c", "/d",
		uint32(0x04), uint32(0x08),
		uint16(8080), uint16(9090),
		uint8(0x01), uint8(0x02),
	)

	// All FS rights handled, empty access lists.
	f.Add(
		uint32(0x1FFFF), uint8(0x0F),
		"/etc", "/home",
		uint32(0x00), uint32(0x00),
		uint16(80), uint16(443),
		uint8(0x00), uint8(0x00),
		uint32(0x1FFFF), uint8(0x0F),
		"/etc", "/tmp",
		uint32(0x00), uint32(0x00),
		uint16(80), uint16(8080),
		uint8(0x00), uint8(0x00),
	)
}

type fuzzMergeConfig struct {
	merge    func(...*landlock.Profile) (*landlock.Profile, error)
	checkInv func(*testing.T, *landlock.Profile, *landlock.Profile, *landlock.Profile)
}

func fuzzMerge(
	t *testing.T,
	cfg fuzzMergeConfig,
	hfsL uint32, hnetL uint8,
	p1L, p2L string,
	am1L, am2L uint32,
	port1L, port2L uint16,
	nm1L, nm2L uint8,
	hfsR uint32, hnetR uint8,
	p1R, p2R string,
	am1R, am2R uint32,
	port1R, port2R uint16,
	nm1R, nm2R uint8,
) {
	t.Helper()

	left := fuzzLandlockProfile(
		hfsL, hnetL, p1L, p2L,
		am1L, am2L, port1L, port2L, nm1L, nm2L,
	)
	right := fuzzLandlockProfile(
		hfsR, hnetR, p1R, p2R,
		am1R, am2R, port1R, port2R, nm1R, nm2R,
	)

	result, err := cfg.merge(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if result == nil {
		t.Fatal("result must not be nil")
	}

	cfg.checkInv(t, result, left, right)

	commuted, err := cfg.merge(right, left)
	if err != nil {
		t.Fatalf("commuted merge: %v", err)
	}

	if !profilesEqual(result, commuted) {
		t.Error("Merge(L,R) != Merge(R,L)")
	}

	single, err := cfg.merge(left)
	if err != nil {
		t.Fatalf("single merge: %v", err)
	}

	idempotent, err := cfg.merge(left, left)
	if err != nil {
		t.Fatalf("idempotent merge: %v", err)
	}

	if !profilesEqual(idempotent, single) {
		t.Error("Merge(X,X) should equal Merge(X)")
	}
}

func fsRightSet(rights []landlock.FSAccessRight) map[landlock.FSAccessRight]struct{} {
	set := make(map[landlock.FSAccessRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

func netRightSet(rights []landlock.NetAccessRight) map[landlock.NetAccessRight]struct{} {
	set := make(map[landlock.NetAccessRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

func pathRuleMap(rules []landlock.PathRule) map[string][]landlock.FSAccessRight {
	result := make(map[string][]landlock.FSAccessRight, len(rules))
	for _, rule := range rules {
		result[rule.Path] = rule.AccessFS
	}

	return result
}

func netRulePortMap(
	rules []landlock.NetRule,
) map[uint16][]landlock.NetAccessRight {
	result := make(map[uint16][]landlock.NetAccessRight, len(rules))
	for _, rule := range rules {
		result[rule.Port] = rule.AccessNet
	}

	return result
}

func assertIntersectInvariants(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertPathsFromInputs(t, result, left, right)
	assertAccessRightsSubset(t, result, left, right)
	assertIntersectOneSidedPaths(t, result, left, right)
	assertNetAccessRightsSubset(t, result, left, right)
	assertIntersectOneSidedNet(t, result, left, right)
	assertHandledFromInputs(t, result, left, right)
	assertHandledCoversInputs(t, result, left, right)
}

func assertPathsFromInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	inputPaths := make(map[string]struct{})
	for _, rule := range left.PathRules {
		inputPaths[rule.Path] = struct{}{}
	}

	for _, rule := range right.PathRules {
		inputPaths[rule.Path] = struct{}{}
	}

	for _, rule := range result.PathRules {
		if _, ok := inputPaths[rule.Path]; !ok {
			t.Errorf("result contains path %q not in any input", rule.Path)
		}
	}
}

func assertAccessRightsSubset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftPaths := pathRuleMap(left.PathRules)
	rightPaths := pathRuleMap(right.PathRules)

	for _, rule := range result.PathRules {
		leftAccess, inLeft := leftPaths[rule.Path]
		rightAccess, inRight := rightPaths[rule.Path]

		if !inLeft || !inRight {
			continue
		}

		leftSet := fsRightSet(leftAccess)
		rightSet := fsRightSet(rightAccess)

		for _, r := range rule.AccessFS {
			_, inL := leftSet[r]
			_, inR := rightSet[r]

			if !inL || !inR {
				t.Errorf("intersect path %q has right %q not in both inputs", rule.Path, r)
			}
		}
	}
}

func assertHandledFromInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftHandledFS := fsRightSet(left.HandledAccessFS)
	rightHandledFS := fsRightSet(right.HandledAccessFS)

	for _, r := range result.HandledAccessFS {
		if _, inL := leftHandledFS[r]; !inL {
			if _, inR := rightHandledFS[r]; !inR {
				t.Errorf("intersect handled FS right %q not in either input", r)
			}
		}
	}

	leftHandledNet := netRightSet(left.HandledAccessNet)
	rightHandledNet := netRightSet(right.HandledAccessNet)

	for _, r := range result.HandledAccessNet {
		if _, inL := leftHandledNet[r]; !inL {
			if _, inR := rightHandledNet[r]; !inR {
				t.Errorf("intersect handled Net right %q not in either input", r)
			}
		}
	}
}

func assertHandledCoversInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertHandledCoversInputsFS(t, result, left, right)
	assertHandledCoversInputsNet(t, result, left, right)
}

func assertHandledCoversInputsFS(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultFS := fsRightSet(result.HandledAccessFS)

	for _, r := range left.HandledAccessFS {
		if _, ok := resultFS[r]; !ok {
			t.Errorf("intersect handled FS missing left input right %q", r)
		}
	}

	for _, r := range right.HandledAccessFS {
		if _, ok := resultFS[r]; !ok {
			t.Errorf("intersect handled FS missing right input right %q", r)
		}
	}
}

func assertHandledCoversInputsNet(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultNet := netRightSet(result.HandledAccessNet)

	for _, r := range left.HandledAccessNet {
		if _, ok := resultNet[r]; !ok {
			t.Errorf("intersect handled Net missing left input right %q", r)
		}
	}

	for _, r := range right.HandledAccessNet {
		if _, ok := resultNet[r]; !ok {
			t.Errorf("intersect handled Net missing right input right %q", r)
		}
	}
}

func assertIntersectOneSidedPaths(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftPaths := pathRuleMap(left.PathRules)
	rightPaths := pathRuleMap(right.PathRules)
	rightHandled := fsRightSet(right.HandledAccessFS)
	leftHandled := fsRightSet(left.HandledAccessFS)

	for _, rule := range result.PathRules {
		_, inLeft := leftPaths[rule.Path]
		_, inRight := rightPaths[rule.Path]

		if inLeft && inRight {
			continue
		}

		handled := rightHandled
		if inRight {
			handled = leftHandled
		}

		for _, r := range rule.AccessFS {
			if _, isHandled := handled[r]; isHandled {
				t.Errorf(
					"intersect one-sided path %q has handled right %q",
					rule.Path, r,
				)
			}
		}
	}
}

func assertNetAccessRightsSubset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftPorts := netRulePortMap(left.NetRules)
	rightPorts := netRulePortMap(right.NetRules)

	for _, rule := range result.NetRules {
		leftAccess, inLeft := leftPorts[rule.Port]
		rightAccess, inRight := rightPorts[rule.Port]

		if !inLeft || !inRight {
			continue
		}

		leftSet := netRightSet(leftAccess)
		rightSet := netRightSet(rightAccess)

		for _, right := range rule.AccessNet {
			_, inL := leftSet[right]
			_, inR := rightSet[right]

			if !inL || !inR {
				t.Errorf(
					"intersect port %d has right %q not in both inputs",
					rule.Port, right,
				)
			}
		}
	}
}

func assertIntersectOneSidedNet(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftPorts := netRulePortMap(left.NetRules)
	rightPorts := netRulePortMap(right.NetRules)
	rightHandled := netRightSet(right.HandledAccessNet)
	leftHandled := netRightSet(left.HandledAccessNet)

	for _, rule := range result.NetRules {
		_, inLeft := leftPorts[rule.Port]
		_, inRight := rightPorts[rule.Port]

		if inLeft && inRight {
			continue
		}

		handled := rightHandled
		if inRight {
			handled = leftHandled
		}

		for _, r := range rule.AccessNet {
			if _, isHandled := handled[r]; isHandled {
				t.Errorf(
					"intersect one-sided port %d has handled right %q",
					rule.Port, r,
				)
			}
		}
	}
}

func assertUnionInvariants(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertUnionPathCoverage(t, result, left, right)
	assertUnionPathRightsSuperset(t, result, left, right)
	assertUnionNetRightsSuperset(t, result, left, right)
	assertUnionHandledSubset(t, result, left, right)
	assertUnionHandledCoversCommon(t, result, left, right)
}

func assertUnionPathCoverage(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultPaths := make(map[string]struct{})
	for _, rule := range result.PathRules {
		resultPaths[rule.Path] = struct{}{}
	}

	for _, input := range []*landlock.Profile{left, right} {
		for _, rule := range input.PathRules {
			if _, ok := resultPaths[rule.Path]; !ok &&
				len(rule.AccessFS) > 0 {
				t.Errorf("path %q missing from union", rule.Path)
			}
		}
	}

	if !slices.IsSortedFunc(
		result.PathRules,
		func(a, b landlock.PathRule) int {
			return cmp.Compare(a.Path, b.Path)
		},
	) {
		t.Error("result path rules are not sorted")
	}
}

func assertUnionHandledSubset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftHandledFS := fsRightSet(left.HandledAccessFS)
	rightHandledFS := fsRightSet(right.HandledAccessFS)

	for _, r := range result.HandledAccessFS {
		_, inL := leftHandledFS[r]
		_, inR := rightHandledFS[r]

		if !inL || !inR {
			t.Errorf("union handled FS right %q not in both inputs", r)
		}
	}

	leftHandledNet := netRightSet(left.HandledAccessNet)
	rightHandledNet := netRightSet(right.HandledAccessNet)

	for _, r := range result.HandledAccessNet {
		_, inL := leftHandledNet[r]
		_, inR := rightHandledNet[r]

		if !inL || !inR {
			t.Errorf("union handled Net right %q not in both inputs", r)
		}
	}
}

func assertUnionHandledCoversCommon(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertUnionHandledCoversCommonFS(t, result, left, right)
	assertUnionHandledCoversCommonNet(t, result, left, right)
}

func assertUnionHandledCoversCommonFS(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultFS := fsRightSet(result.HandledAccessFS)
	rightFS := fsRightSet(right.HandledAccessFS)

	for _, fsRight := range left.HandledAccessFS {
		if _, inR := rightFS[fsRight]; !inR {
			continue
		}

		if _, ok := resultFS[fsRight]; !ok {
			t.Errorf("union handled FS missing common right %q", fsRight)
		}
	}
}

func assertUnionHandledCoversCommonNet(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultNet := netRightSet(result.HandledAccessNet)
	rightNet := netRightSet(right.HandledAccessNet)

	for _, netRight := range left.HandledAccessNet {
		if _, inR := rightNet[netRight]; !inR {
			continue
		}

		if _, ok := resultNet[netRight]; !ok {
			t.Errorf("union handled Net missing common right %q", netRight)
		}
	}
}

func assertUnionPathRightsSuperset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultPaths := pathRuleMap(result.PathRules)
	leftPaths := pathRuleMap(left.PathRules)
	rightPaths := pathRuleMap(right.PathRules)

	assertPathRightsPresent(t, leftPaths, rightPaths, resultPaths)
	assertPathRightsPresent(t, rightPaths, leftPaths, resultPaths)
}

func assertPathRightsPresent(
	t *testing.T,
	source, other map[string][]landlock.FSAccessRight,
	result map[string][]landlock.FSAccessRight,
) {
	t.Helper()

	for path, access := range source {
		if _, inOther := other[path]; !inOther {
			continue
		}

		resultAccess, inResult := result[path]
		if !inResult {
			t.Errorf("union missing shared path %q", path)

			continue
		}

		resultSet := fsRightSet(resultAccess)

		for _, r := range access {
			if _, ok := resultSet[r]; !ok {
				t.Errorf("union path %q missing right %q", path, r)
			}
		}
	}
}

func assertUnionNetRightsSuperset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultPorts := netRulePortMap(result.NetRules)
	leftPorts := netRulePortMap(left.NetRules)
	rightPorts := netRulePortMap(right.NetRules)

	assertNetRightsPresent(t, leftPorts, rightPorts, resultPorts)
	assertNetRightsPresent(t, rightPorts, leftPorts, resultPorts)
}

func assertNetRightsPresent(
	t *testing.T,
	source, other map[uint16][]landlock.NetAccessRight,
	result map[uint16][]landlock.NetAccessRight,
) {
	t.Helper()

	for port, access := range source {
		if _, inOther := other[port]; !inOther {
			continue
		}

		resultAccess, inResult := result[port]
		if !inResult {
			t.Errorf("union missing shared port %d", port)

			continue
		}

		resultSet := netRightSet(resultAccess)

		for _, r := range access {
			if _, ok := resultSet[r]; !ok {
				t.Errorf("union port %d missing right %q", port, r)
			}
		}
	}
}

func profilesEqual(a, b *landlock.Profile) bool {
	return slices.Equal(a.HandledAccessFS, b.HandledAccessFS) &&
		slices.Equal(a.HandledAccessNet, b.HandledAccessNet) &&
		pathRulesEqual(a.PathRules, b.PathRules) &&
		netRulesEqual(a.NetRules, b.NetRules)
}

func pathRulesEqual(left, right []landlock.PathRule) bool {
	if len(left) != len(right) {
		return false
	}

	for idx := range left {
		if left[idx].Path != right[idx].Path {
			return false
		}

		if !slices.Equal(left[idx].AccessFS, right[idx].AccessFS) {
			return false
		}
	}

	return true
}

func netRulesEqual(left, right []landlock.NetRule) bool {
	if len(left) != len(right) {
		return false
	}

	for idx := range left {
		if left[idx].Port != right[idx].Port {
			return false
		}

		if !slices.Equal(left[idx].AccessNet, right[idx].AccessNet) {
			return false
		}
	}

	return true
}

func FuzzLandlockIntersect(f *testing.F) {
	addLandlockFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:    landlock.Intersect,
		checkInv: assertIntersectInvariants,
	}

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		fuzzMerge(t, cfg,
			hfsL, hnetL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
			hfsR, hnetR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)
	})
}

func FuzzLandlockUnion(f *testing.F) {
	addLandlockFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:    landlock.Union,
		checkInv: assertUnionInvariants,
	}

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		fuzzMerge(t, cfg,
			hfsL, hnetL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
			hfsR, hnetR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)
	})
}
