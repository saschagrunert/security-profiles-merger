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

type testProfile struct {
	value int
}

func cloneTestProfile(p *testProfile) *testProfile {
	return &testProfile{value: p.value}
}

func addTestProfiles(a, b *testProfile) *testProfile {
	return &testProfile{value: a.value + b.value}
}

func TestFoldEmpty(t *testing.T) {
	t.Parallel()

	_, err := merge.Fold[testProfile](nil, cloneTestProfile, addTestProfiles)
	if err == nil {
		t.Fatal("expected error for empty profiles")
	}
}

func TestFoldNil(t *testing.T) {
	t.Parallel()

	_, err := merge.Fold([]*testProfile{nil}, cloneTestProfile, addTestProfiles)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestFoldNilAtIndex(t *testing.T) {
	t.Parallel()

	valid := &testProfile{value: 1}

	_, err := merge.Fold([]*testProfile{valid, nil}, cloneTestProfile, addTestProfiles)
	if err == nil {
		t.Fatal("expected error for nil profile at index 1")
	}
}

func TestFoldSingle(t *testing.T) {
	t.Parallel()

	original := &testProfile{value: 42}

	result, err := merge.Fold([]*testProfile{original}, cloneTestProfile, addTestProfiles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.value != 42 {
		t.Errorf("value = %d, want 42", result.value)
	}

	if result == original {
		t.Error("result should be a clone, not the same pointer")
	}
}

func TestFoldTwo(t *testing.T) {
	t.Parallel()

	result, err := merge.Fold(
		[]*testProfile{{value: 10}, {value: 20}},
		cloneTestProfile, addTestProfiles,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.value != 30 {
		t.Errorf("value = %d, want 30", result.value)
	}
}

func TestFoldThree(t *testing.T) {
	t.Parallel()

	result, err := merge.Fold(
		[]*testProfile{{value: 1}, {value: 2}, {value: 3}},
		cloneTestProfile, addTestProfiles,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.value != 6 {
		t.Errorf("value = %d, want 6", result.value)
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
