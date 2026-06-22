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
	"fmt"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
)

func buildAppArmorProfile(numPaths int) *apparmor.Profile {
	caps := make([]string, 0, numPaths)
	readOnly := make([]string, 0, numPaths)
	writeOnly := make([]string, 0, numPaths)
	readWrite := make([]string, 0, numPaths)
	executables := make([]string, 0, numPaths)

	for idx := range numPaths {
		caps = append(caps, fmt.Sprintf("CAP_%d", idx))
		readOnly = append(readOnly, fmt.Sprintf("/read/%d", idx))
		writeOnly = append(writeOnly, fmt.Sprintf("/write/%d", idx))
		readWrite = append(readWrite, fmt.Sprintf("/rw/%d", idx))
		executables = append(executables, fmt.Sprintf("/usr/bin/prog%d", idx))
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: executables,
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: writeOnly,
			ReadWritePaths: readWrite,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: caps,
		},
	}
}

func BenchmarkAppArmorIntersect(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildAppArmorProfile(numPaths)
		right := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			for range b.N {
				result, err := apparmor.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkAppArmorUnion(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildAppArmorProfile(numPaths)
		right := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			for range b.N {
				result, err := apparmor.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}
