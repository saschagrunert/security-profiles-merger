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

// Package merge provides shared utilities for security profile merge operations.
package merge

import "errors"

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = errors.New("at least one profile is required")
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = errors.New("profile must not be nil")
)

// IntersectSlice returns elements present in both left and right.
func IntersectSlice[T comparable](left, right []T) []T {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}

	rightSet := make(map[T]struct{}, len(right))
	for _, val := range right {
		rightSet[val] = struct{}{}
	}

	var result []T

	for _, val := range left {
		if _, ok := rightSet[val]; ok {
			result = append(result, val)
		}
	}

	return result
}

// UnionSlice returns all unique elements from left and right, preserving order.
func UnionSlice[T comparable](left, right []T) []T {
	seen := make(map[T]struct{})

	var result []T

	for _, val := range left {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	for _, val := range right {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	return result
}
