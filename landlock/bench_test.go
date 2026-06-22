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
	"fmt"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/landlock"
)

func buildLandlockProfile(numPaths int) *landlock.Profile {
	pathRules := make([]landlock.PathRule, 0, numPaths)
	netRules := make([]landlock.NetRule, 0, numPaths)

	for idx := range numPaths {
		pathRules = append(pathRules, landlock.PathRule{
			Path: fmt.Sprintf("/path/%d", idx),
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
				landlock.FSAccessExecute,
			},
		})

		netRules = append(netRules, landlock.NetRule{
			Port: uint16(idx + 1),
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessConnectTCP,
			},
		})
	}

	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessConnectTCP,
		},
		PathRules: pathRules,
		NetRules:  netRules,
	}
}

func BenchmarkLandlockIntersect(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildLandlockProfile(numPaths)
		right := buildLandlockProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			for range b.N {
				result, err := landlock.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkLandlockUnion(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildLandlockProfile(numPaths)
		right := buildLandlockProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			for range b.N {
				result, err := landlock.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}
