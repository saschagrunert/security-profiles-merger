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

package merge_test

import (
	"slices"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

func intersectCases() []struct {
	name  string
	left  []string
	right []string
	want  []string
} {
	return []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{name: "both empty", left: nil, right: nil, want: nil},
		{name: "left empty", left: nil, right: []string{"a", "b"}, want: nil},
		{name: "right empty", left: []string{"a", "b"}, right: nil, want: nil},
		{name: "no overlap", left: []string{"a", "b"}, right: []string{"c", "d"}, want: nil},
		{
			name: "full overlap", left: []string{"a", "b"},
			right: []string{"a", "b"}, want: []string{"a", "b"},
		},
		{
			name: "partial overlap", left: []string{"a", "b", "c"},
			right: []string{"b", "d"}, want: []string{"b"},
		},
		{
			name: "duplicates in input", left: []string{"a", "a", "b"},
			right: []string{"a", "b", "b"}, want: []string{"a", "a", "b"},
		},
	}
}

func TestIntersectSlice(t *testing.T) {
	t.Parallel()

	for _, testCase := range intersectCases() {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := merge.IntersectSlice(testCase.left, testCase.right)
			if !slices.Equal(got, testCase.want) {
				t.Errorf(
					"IntersectSlice(%v, %v) = %v, want %v",
					testCase.left, testCase.right, got, testCase.want,
				)
			}
		})
	}
}

func unionCases() []struct {
	name  string
	left  []string
	right []string
	want  []string
} {
	return []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{name: "both empty", left: nil, right: nil, want: nil},
		{name: "left empty", left: nil, right: []string{"a", "b"}, want: []string{"a", "b"}},
		{name: "right empty", left: []string{"a", "b"}, right: nil, want: []string{"a", "b"}},
		{
			name: "no overlap", left: []string{"a", "b"},
			right: []string{"c", "d"}, want: []string{"a", "b", "c", "d"},
		},
		{
			name: "full overlap", left: []string{"a", "b"},
			right: []string{"a", "b"}, want: []string{"a", "b"},
		},
		{
			name: "partial overlap", left: []string{"a", "b"},
			right: []string{"b", "c"}, want: []string{"a", "b", "c"},
		},
		{
			name: "duplicates in input", left: []string{"a", "a", "b"},
			right: []string{"b", "c", "c"}, want: []string{"a", "b", "c"},
		},
	}
}

func TestUnionSlice(t *testing.T) {
	t.Parallel()

	for _, testCase := range unionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := merge.UnionSlice(testCase.left, testCase.right)
			if !slices.Equal(got, testCase.want) {
				t.Errorf(
					"UnionSlice(%v, %v) = %v, want %v",
					testCase.left, testCase.right, got, testCase.want,
				)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrNoProfiles", func(t *testing.T) {
		t.Parallel()

		if merge.ErrNoProfiles == nil {
			t.Fatal("ErrNoProfiles should not be nil")
		}

		const want = "at least one profile is required"
		if merge.ErrNoProfiles.Error() != want {
			t.Errorf("ErrNoProfiles = %q, want %q", merge.ErrNoProfiles.Error(), want)
		}
	})

	t.Run("ErrNilProfile", func(t *testing.T) {
		t.Parallel()

		if merge.ErrNilProfile == nil {
			t.Fatal("ErrNilProfile should not be nil")
		}

		const want = "profile must not be nil"
		if merge.ErrNilProfile.Error() != want {
			t.Errorf("ErrNilProfile = %q, want %q", merge.ErrNilProfile.Error(), want)
		}
	})
}
