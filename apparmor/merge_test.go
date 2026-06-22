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
	"slices"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
)

const (
	capNetAdmin  = "NET_ADMIN"
	capSysTime   = "SYS_TIME"
	capChown     = "CHOWN"
	capSysPtrace = "SYS_PTRACE"

	pathEtcConfig = "/etc/config"
	pathVarLog    = "/var/log"
	pathTmp       = "/tmp"
	pathBinPython = "/usr/bin/python"
	pathBinBash   = "/usr/bin/bash"
	pathBinCurl   = "/usr/bin/curl"
	pathLibC      = "/usr/lib/libc.so"
	pathLibM      = "/usr/lib/libm.so"
)

func boolPtr(val bool) *bool { return &val }

func TestIntersectEmpty(t *testing.T) {
	t.Parallel()

	_, err := apparmor.Intersect()
	if err == nil {
		t.Fatal("expected error for empty profiles")
	}
}

func TestIntersectNil(t *testing.T) {
	t.Parallel()

	_, err := apparmor.Intersect(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestIntersectSingleProfile(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Capabilities.AllowedCapabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(result.Capabilities.AllowedCapabilities))
	}

	if len(result.Executable.AllowedExecutables) != 1 {
		t.Errorf("expected 1 executable, got %d", len(result.Executable.AllowedExecutables))
	}

	if len(result.Filesystem.ReadOnlyPaths) != 1 {
		t.Errorf("expected 1 read-only path, got %d", len(result.Filesystem.ReadOnlyPaths))
	}

	if !*result.Network.AllowRaw {
		t.Error("AllowRaw should be true")
	}
}

func TestIntersectCapabilities(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capChown},
		},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysPtrace, capChown},
		},
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capChown, capNetAdmin}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestUnionCapabilities(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capNetAdmin, capSysTime}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestIntersectNetwork(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw == nil || *result.Network.AllowRaw {
		t.Error("AllowRaw should be false (AND of true, false)")
	}

	if result.Network.Protocols.AllowTCP == nil || !*result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be true (AND of true, true)")
	}

	if result.Network.Protocols.AllowUDP == nil || *result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be false (AND of true, false)")
	}
}

func TestUnionNetwork(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw == nil || !*result.Network.AllowRaw {
		t.Error("AllowRaw should be true (OR of false, true)")
	}

	if result.Network.Protocols.AllowTCP == nil || !*result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be true (OR of false, true)")
	}

	if result.Network.Protocols.AllowUDP == nil || !*result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be true (OR of true, false)")
	}
}

func TestIntersectFilesystem(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{pathEtcConfig}) {
		t.Errorf("ReadOnlyPaths = %v, want [%s]", result.Filesystem.ReadOnlyPaths, pathEtcConfig)
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, []string{pathTmp}) {
		t.Errorf("WriteOnlyPaths = %v, want [%s]", result.Filesystem.WriteOnlyPaths, pathTmp)
	}

	if result.Filesystem.ReadWritePaths != nil {
		t.Errorf("ReadWritePaths = %v, want nil", result.Filesystem.ReadWritePaths)
	}
}

func TestUnionFilesystem(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathVarLog},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadWritePaths, []string{pathEtcConfig}) {
		t.Errorf("ReadWritePaths = %v, want [%s]", result.Filesystem.ReadWritePaths, pathEtcConfig)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{pathVarLog}) {
		t.Errorf("ReadOnlyPaths = %v, want [%s]", result.Filesystem.ReadOnlyPaths, pathVarLog)
	}
}

func TestIntersectExecutable(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinBash, pathBinCurl},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinCurl},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantExec := []string{pathBinCurl, pathBinPython}
	if !slices.Equal(result.Executable.AllowedExecutables, wantExec) {
		t.Errorf("AllowedExecutables = %v, want %v", result.Executable.AllowedExecutables, wantExec)
	}

	wantLib := []string{pathLibC}
	if !slices.Equal(result.Executable.AllowedLibraries, wantLib) {
		t.Errorf("AllowedLibraries = %v, want %v", result.Executable.AllowedLibraries, wantLib)
	}
}

func TestUnionExecutable(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinBash},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{pathBinBash, pathBinPython}
	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf("AllowedExecutables = %v, want %v", result.Executable.AllowedExecutables, want)
	}
}

func TestIntersectThreeProfiles(t *testing.T) {
	t.Parallel()

	first := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capChown},
		},
	}

	second := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown, capSysPtrace},
		},
	}

	third := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown, capSysPtrace, "DAC_OVERRIDE"},
		},
	}

	result, err := apparmor.Intersect(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capChown}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestIntersectNilFields(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
	}

	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Capabilities == nil {
		t.Fatal("capabilities should not be nil (one side has it)")
	}

	want := []string{capNetAdmin}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestNilProfileAtIndex(t *testing.T) {
	t.Parallel()

	valid := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	_, err := apparmor.Intersect(valid, nil)
	if err == nil {
		t.Fatal("expected error for nil profile at index 1")
	}

	_, err = apparmor.Union(valid, nil)
	if err == nil {
		t.Fatal("expected error for nil profile at index 1 (union)")
	}
}

func TestIntersectExecutableLeftNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Executable == nil {
		t.Fatal("executable should not be nil")
	}

	if !slices.Equal(result.Executable.AllowedExecutables, []string{pathBinPython}) {
		t.Errorf(
			"AllowedExecutables = %v, want [%s]",
			result.Executable.AllowedExecutables, pathBinPython,
		)
	}
}

func TestIntersectExecutableRightNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Executable == nil {
		t.Fatal("executable should not be nil")
	}

	if !slices.Equal(result.Executable.AllowedExecutables, []string{pathBinBash}) {
		t.Errorf(
			"AllowedExecutables = %v, want [%s]",
			result.Executable.AllowedExecutables, pathBinBash,
		)
	}
}

func TestIntersectFilesystemLeftNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		t.Fatal("filesystem should not be nil")
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{pathEtcConfig}) {
		t.Errorf("ReadOnlyPaths = %v, want [%s]", result.Filesystem.ReadOnlyPaths, pathEtcConfig)
	}
}

func TestIntersectFilesystemRightNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		t.Fatal("filesystem should not be nil")
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, []string{pathVarLog}) {
		t.Errorf("WriteOnlyPaths = %v, want [%s]", result.Filesystem.WriteOnlyPaths, pathVarLog)
	}
}

func TestIntersectNetworkLeftNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network == nil {
		t.Fatal("network should not be nil")
	}

	if result.Network.AllowRaw == nil || !*result.Network.AllowRaw {
		t.Error("AllowRaw should be true (cloned from right)")
	}
}

func TestIntersectNetworkRightNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(false),
			Protocols: nil,
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network == nil {
		t.Fatal("network should not be nil")
	}

	if result.Network.AllowRaw == nil || *result.Network.AllowRaw {
		t.Error("AllowRaw should be false (cloned from left)")
	}

	if result.Network.Protocols != nil {
		t.Error("Protocols should be nil")
	}
}

func TestIntersectNetworkLeftProtocolsNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(true),
			Protocols: nil,
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.Protocols == nil {
		t.Fatal("Protocols should not be nil (cloned from right)")
	}

	if result.Network.Protocols.AllowTCP == nil || !*result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be true")
	}
}

func TestIntersectNetworkRightProtocolsNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(true),
			Protocols: nil,
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.Protocols == nil {
		t.Fatal("Protocols should not be nil (cloned from left)")
	}

	if result.Network.Protocols.AllowUDP == nil || !*result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be true")
	}
}

func TestIntersectBoolOneNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: nil,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: nil,
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: nil,
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw == nil || !*result.Network.AllowRaw {
		t.Error("AllowRaw should be true (left nil, right true)")
	}

	if result.Network.Protocols.AllowTCP == nil || !*result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be true (left true, right nil)")
	}

	if result.Network.Protocols.AllowUDP == nil || *result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be false (left nil, right false)")
	}
}

func TestUnionBoolOneNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: nil,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: nil,
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: nil,
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw == nil || *result.Network.AllowRaw {
		t.Error("AllowRaw should be false (left nil, right false)")
	}

	if result.Network.Protocols.AllowTCP == nil || *result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be false (left false, right nil)")
	}

	if result.Network.Protocols.AllowUDP == nil || !*result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be true (left nil, right true)")
	}
}

func TestIntersectBoolBothNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: nil,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: nil,
				AllowUDP: nil,
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: nil,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: nil,
				AllowUDP: nil,
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw != nil {
		t.Error("AllowRaw should be nil when both inputs are nil")
	}

	if result.Network.Protocols.AllowTCP != nil {
		t.Error("AllowTCP should be nil when both inputs are nil")
	}
}

func TestIntersectCapabilitiesOneNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Capabilities == nil {
		t.Fatal("capabilities should not be nil")
	}

	if !slices.Equal(result.Capabilities.AllowedCapabilities, []string{capNetAdmin}) {
		t.Errorf(
			"capabilities = %v, want [%s]",
			result.Capabilities.AllowedCapabilities, capNetAdmin,
		)
	}
}

func TestUnionCapabilitiesOneNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capSysTime},
		},
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Capabilities == nil {
		t.Fatal("capabilities should not be nil")
	}

	if !slices.Equal(result.Capabilities.AllowedCapabilities, []string{capSysTime}) {
		t.Errorf(
			"capabilities = %v, want [%s]",
			result.Capabilities.AllowedCapabilities, capSysTime,
		)
	}
}

func TestFilesystemWriteOnlyOnly(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathVarLog, pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		t.Fatal("filesystem should not be nil")
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, []string{pathVarLog}) {
		t.Errorf("WriteOnlyPaths = %v, want [%s]", result.Filesystem.WriteOnlyPaths, pathVarLog)
	}

	if result.Filesystem.ReadOnlyPaths != nil {
		t.Errorf("ReadOnlyPaths = %v, want nil", result.Filesystem.ReadOnlyPaths)
	}
}

func TestFilesystemIntersectNoOverlap(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		t.Fatal("filesystem should not be nil (both inputs were non-nil)")
	}

	if len(result.Filesystem.ReadOnlyPaths) != 0 {
		t.Errorf("ReadOnlyPaths = %v, want empty", result.Filesystem.ReadOnlyPaths)
	}

	if len(result.Filesystem.WriteOnlyPaths) != 0 {
		t.Errorf("WriteOnlyPaths = %v, want empty", result.Filesystem.WriteOnlyPaths)
	}

	if len(result.Filesystem.ReadWritePaths) != 0 {
		t.Errorf("ReadWritePaths = %v, want empty", result.Filesystem.ReadWritePaths)
	}
}

func TestMergeDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capChown}},
	}

	origLeft := slices.Clone(left.Capabilities.AllowedCapabilities)
	origRight := slices.Clone(right.Capabilities.AllowedCapabilities)

	_, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(left.Capabilities.AllowedCapabilities, origLeft) {
		t.Error("Intersect mutated first input")
	}

	if !slices.Equal(right.Capabilities.AllowedCapabilities, origRight) {
		t.Error("Intersect mutated second input")
	}
}

func TestMergeDoesNotMutateAllFields(t *testing.T) {
	t.Parallel()

	left := buildFullProfile()

	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown},
		},
	}

	snap := snapshotProfile(left)

	_, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertProfileUnchanged(t, left, &snap)
}

func buildFullProfile() *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinBash},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: []string{pathTmp},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}
}

type profileSnapshot struct {
	executables []string
	libraries   []string
	readOnly    []string
	writeOnly   []string
	readWrite   []string
	allowRaw    bool
	allowTCP    bool
	allowUDP    bool
	caps        []string
}

func snapshotProfile(profile *apparmor.Profile) profileSnapshot {
	return profileSnapshot{
		executables: slices.Clone(profile.Executable.AllowedExecutables),
		libraries:   slices.Clone(profile.Executable.AllowedLibraries),
		readOnly:    slices.Clone(profile.Filesystem.ReadOnlyPaths),
		writeOnly:   slices.Clone(profile.Filesystem.WriteOnlyPaths),
		readWrite:   slices.Clone(profile.Filesystem.ReadWritePaths),
		allowRaw:    *profile.Network.AllowRaw,
		allowTCP:    *profile.Network.Protocols.AllowTCP,
		allowUDP:    *profile.Network.Protocols.AllowUDP,
		caps:        slices.Clone(profile.Capabilities.AllowedCapabilities),
	}
}

func assertProfileUnchanged(t *testing.T, profile *apparmor.Profile, snap *profileSnapshot) {
	t.Helper()

	if !slices.Equal(profile.Executable.AllowedExecutables, snap.executables) {
		t.Error("merge mutated AllowedExecutables")
	}

	if !slices.Equal(profile.Executable.AllowedLibraries, snap.libraries) {
		t.Error("merge mutated AllowedLibraries")
	}

	if !slices.Equal(profile.Filesystem.ReadOnlyPaths, snap.readOnly) {
		t.Error("merge mutated ReadOnlyPaths")
	}

	if !slices.Equal(profile.Filesystem.WriteOnlyPaths, snap.writeOnly) {
		t.Error("merge mutated WriteOnlyPaths")
	}

	if !slices.Equal(profile.Filesystem.ReadWritePaths, snap.readWrite) {
		t.Error("merge mutated ReadWritePaths")
	}

	if *profile.Network.AllowRaw != snap.allowRaw {
		t.Error("merge mutated AllowRaw")
	}

	if *profile.Network.Protocols.AllowTCP != snap.allowTCP {
		t.Error("merge mutated AllowTCP")
	}

	if *profile.Network.Protocols.AllowUDP != snap.allowUDP {
		t.Error("merge mutated AllowUDP")
	}

	if !slices.Equal(profile.Capabilities.AllowedCapabilities, snap.caps) {
		t.Error("merge mutated AllowedCapabilities")
	}
}
