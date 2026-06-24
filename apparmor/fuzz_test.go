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

package apparmor_test

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
)

func fuzzAppArmorProfile(
	cap1, cap2, path1, path2 string,
	allowRaw, allowTCP, allowUDP bool,
) *apparmor.Profile {
	if cap1 == "" {
		cap1 = "NET_ADMIN"
	}

	if cap2 == "" {
		cap2 = "SYS_TIME"
	}

	path1 = sanitizeFuzzPath(path1, "/etc/config")
	path2 = sanitizeFuzzPath(path2, "/var/log")

	if path2 == path1 {
		path2 = path1 + "_alt"
	}

	if cap2 == cap1 {
		cap2 = cap1 + "_ALT"
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{path1},
			AllowedLibraries:   []string{path2},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{path1},
			WriteOnlyPaths: []string{path2},
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: &allowRaw,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &allowTCP,
				AllowUDP: &allowUDP,
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{cap1, cap2},
		},
	}
}

func sanitizeFuzzPath(fuzzPath, fallback string) string {
	if fuzzPath == "" {
		return fallback
	}

	if strings.ContainsAny(fuzzPath, "*?{") {
		return fallback
	}

	return filepath.Clean(fuzzPath)
}

func addAppArmorFuzzSeeds(f *testing.F) {
	f.Helper()

	// Identical profiles.
	f.Add(
		"NET_ADMIN", "SYS_TIME", "/etc/config", "/var/log", true, true, false,
		"NET_ADMIN", "SYS_TIME", "/etc/config", "/var/log", true, true, false,
	)

	// Disjoint capabilities.
	f.Add(
		"NET_ADMIN", "SYS_TIME", "/etc/config", "/var/log", true, true, false,
		"CHOWN", "SYS_PTRACE", "/etc/config", "/var/log", false, false, true,
	)

	// Overlapping paths.
	f.Add(
		"NET_ADMIN", "CHOWN", "/etc/config", "/tmp", true, true, true,
		"NET_ADMIN", "CHOWN", "/tmp", "/var/log", false, true, false,
	)

	// Nil-like sub-rules (empty strings).
	f.Add(
		"NET_ADMIN", "NET_ADMIN", "/a", "/b", false, false, false,
		"CHOWN", "CHOWN", "/c", "/d", true, true, true,
	)

	// Only network populated, capabilities nil-like.
	f.Add(
		"CAP_A", "CAP_A", "/x", "/y", true, false, true,
		"CAP_B", "CAP_B", "/x", "/z", false, true, false,
	)
}

type fuzzAppArmorMergeConfig struct {
	merge    func(...*apparmor.Profile) (*apparmor.Profile, error)
	checkCap func(*testing.T, *apparmor.Profile, *apparmor.Profile, *apparmor.Profile)
}

func fuzzAppArmorMerge(
	t *testing.T,
	cfg fuzzAppArmorMergeConfig,
	cap1L, cap2L, path1L, path2L string,
	rawL, tcpL, udpL bool,
	cap1R, cap2R, path1R, path2R string,
	rawR, tcpR, udpR bool,
) {
	t.Helper()

	left := fuzzAppArmorProfile(cap1L, cap2L, path1L, path2L, rawL, tcpL, udpL)
	right := fuzzAppArmorProfile(cap1R, cap2R, path1R, path2R, rawR, tcpR, udpR)

	result, err := cfg.merge(left, right)
	if err != nil {
		return
	}

	if result == nil {
		t.Fatal("result must not be nil")
	}

	cfg.checkCap(t, result, left, right)

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

	if idempotent.Capabilities == nil && left.Capabilities != nil {
		t.Fatal("idempotent merge lost capabilities")
	}
}

func capSet(caps []string) map[string]struct{} {
	set := make(map[string]struct{}, len(caps))
	for _, cap := range caps {
		set[cap] = struct{}{}
	}

	return set
}

func assertCapsSubset(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Capabilities == nil {
		return
	}

	leftCaps := capSet(left.Capabilities.AllowedCapabilities)
	rightCaps := capSet(right.Capabilities.AllowedCapabilities)

	for _, cap := range result.Capabilities.AllowedCapabilities {
		_, inLeft := leftCaps[cap]
		_, inRight := rightCaps[cap]

		if !inLeft || !inRight {
			t.Errorf("intersect result has cap %q not in both inputs", cap)
		}
	}
}

func assertCapsSuperset(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Capabilities == nil {
		return
	}

	resultCaps := capSet(result.Capabilities.AllowedCapabilities)

	for _, profiles := range []*apparmor.Profile{left, right} {
		if profiles.Capabilities == nil {
			continue
		}

		for _, cap := range profiles.Capabilities.AllowedCapabilities {
			if _, ok := resultCaps[cap]; !ok {
				t.Errorf("union result missing cap %q from input", cap)
			}
		}
	}
}

func FuzzAppArmorIntersect(f *testing.F) {
	addAppArmorFuzzSeeds(f)

	cfg := fuzzAppArmorMergeConfig{
		merge:    apparmor.Intersect,
		checkCap: assertCapsSubset,
	}

	f.Fuzz(func(
		t *testing.T,
		cap1L, cap2L, path1L, path2L string,
		rawL, tcpL, udpL bool,
		cap1R, cap2R, path1R, path2R string,
		rawR, tcpR, udpR bool,
	) {
		fuzzAppArmorMerge(t, cfg,
			cap1L, cap2L, path1L, path2L, rawL, tcpL, udpL,
			cap1R, cap2R, path1R, path2R, rawR, tcpR, udpR,
		)
	})
}

func FuzzAppArmorUnion(f *testing.F) {
	addAppArmorFuzzSeeds(f)

	cfg := fuzzAppArmorMergeConfig{
		merge:    apparmor.Union,
		checkCap: assertCapsSuperset,
	}

	f.Fuzz(func(
		t *testing.T,
		cap1L, cap2L, path1L, path2L string,
		rawL, tcpL, udpL bool,
		cap1R, cap2R, path1R, path2R string,
		rawR, tcpR, udpR bool,
	) {
		fuzzAppArmorMerge(t, cfg,
			cap1L, cap2L, path1L, path2L, rawL, tcpL, udpL,
			cap1R, cap2R, path1R, path2R, rawR, tcpR, udpR,
		)
	})
}
