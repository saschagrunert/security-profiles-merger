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
	"reflect"
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
	}
}

func allNetRightsForFuzz() []landlock.NetAccessRight {
	return []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}
}

func fuzzLandlockProfile(
	handledFSMask, handledNetMask uint8,
	path1, path2 string,
	accessMask1, accessMask2 uint8,
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

	pathRules := buildFuzzPathRules(
		path1, path2, accessMask1, accessMask2,
	)
	netRules := buildFuzzNetRules(
		port1, port2, netMask1, netMask2,
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
	accessMask1, accessMask2 uint8,
) []landlock.PathRule {
	var pathRules []landlock.PathRule

	if access := pickFSRights(accessMask1); len(access) > 0 {
		pathRules = append(pathRules, landlock.PathRule{
			Path:     path1,
			AccessFS: access,
		})
	}

	if access := pickFSRights(accessMask2); len(access) > 0 {
		pathRules = append(pathRules, landlock.PathRule{
			Path:     path2,
			AccessFS: access,
		})
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

	if access := pickNetRights(netMask2); len(access) > 0 {
		netRules = append(netRules, landlock.NetRule{
			Port:      port2,
			AccessNet: access,
		})
	}

	return netRules
}

func pickFSRights(mask uint8) []landlock.FSAccessRight {
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
		uint8(0x07), uint8(0x03),
		"/etc", "/home",
		uint8(0x05), uint8(0x03),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint8(0x07), uint8(0x03),
		"/etc", "/tmp",
		uint8(0x01), uint8(0x06),
		uint16(80), uint16(8080),
		uint8(0x03), uint8(0x01),
	)

	// Identical profiles.
	f.Add(
		uint8(0x03), uint8(0x01),
		"/etc", "/home",
		uint8(0x01), uint8(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint8(0x03), uint8(0x01),
		"/etc", "/home",
		uint8(0x01), uint8(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)

	// Disjoint paths.
	f.Add(
		uint8(0xFF), uint8(0x03),
		"/a", "/b",
		uint8(0x01), uint8(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint8(0xFF), uint8(0x03),
		"/c", "/d",
		uint8(0x04), uint8(0x08),
		uint16(8080), uint16(9090),
		uint8(0x01), uint8(0x02),
	)
}

type fuzzMergeConfig struct {
	merge    func(...*landlock.Profile) (*landlock.Profile, error)
	checkInv func(*testing.T, *landlock.Profile, *landlock.Profile, *landlock.Profile)
}

func fuzzMerge(
	t *testing.T,
	cfg fuzzMergeConfig,
	hfsL, hnetL uint8,
	p1L, p2L string,
	am1L, am2L uint8,
	port1L, port2L uint16,
	nm1L, nm2L uint8,
	hfsR, hnetR uint8,
	p1R, p2R string,
	am1R, am2R uint8,
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

	if !reflect.DeepEqual(result, commuted) {
		t.Error("Merge(L,R) != Merge(R,L)")
	}

	idempotent, err := cfg.merge(left, left)
	if err != nil {
		t.Fatalf("idempotent merge: %v", err)
	}

	if idempotent == nil {
		t.Fatal("idempotent result must not be nil")
	}
}

func assertIntersectInvariants(
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
			t.Errorf(
				"result contains path %q not in any input",
				rule.Path,
			)
		}
	}
}

func assertUnionInvariants(
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

func FuzzLandlockIntersect(f *testing.F) {
	addLandlockFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:    landlock.Intersect,
		checkInv: assertIntersectInvariants,
	}

	f.Fuzz(func(
		t *testing.T,
		hfsL, hnetL uint8,
		p1L, p2L string,
		am1L, am2L uint8,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR, hnetR uint8,
		p1R, p2R string,
		am1R, am2R uint8,
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
		hfsL, hnetL uint8,
		p1L, p2L string,
		am1L, am2L uint8,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR, hnetR uint8,
		p1R, p2R string,
		am1R, am2R uint8,
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
