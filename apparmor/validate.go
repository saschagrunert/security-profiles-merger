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

package apparmor

import (
	"errors"
	"fmt"
)

var (
	// ErrDuplicatePath is returned when a path appears in multiple
	// filesystem rule categories within the same profile.
	ErrDuplicatePath = errors.New("duplicate path across filesystem categories")

	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = errors.New("empty path")
)

// Validate checks an AppArmor profile for structural issues.
// Capability names are not validated against a fixed set because the
// kernel may support capabilities unknown to this library. Filesystem
// paths and executable paths are also not validated.
//
// The checks catch issues that would produce confusing merge results:
// duplicate paths across filesystem categories, which expand into
// ambiguous permission sets. All validation failures are collected and
// returned together.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	err := validateEmptyPathsInProfile(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile.Filesystem != nil {
		err := validateFilesystemPaths(profile.Filesystem)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func validateEmptyPaths(context string, paths []string) []error {
	var errs []error

	for idx, path := range paths {
		if path == "" {
			errs = append(errs, fmt.Errorf(
				"%s[%d]: %w", context, idx, ErrEmptyPath,
			))
		}
	}

	return errs
}

// validateEmptyPathsInProfile checks for empty paths before normalization,
// since path.Clean("") returns "." which would bypass Validate's check.
func validateEmptyPathsInProfile(profile *Profile) error {
	var errs []error

	if profile.Executable != nil {
		errs = append(errs, validateEmptyPaths(
			"AllowedExecutables", profile.Executable.AllowedExecutables,
		)...)
		errs = append(errs, validateEmptyPaths(
			"AllowedLibraries", profile.Executable.AllowedLibraries,
		)...)
	}

	if profile.Filesystem != nil {
		errs = append(errs, validateEmptyPaths(
			"ReadOnlyPaths", profile.Filesystem.ReadOnlyPaths,
		)...)
		errs = append(errs, validateEmptyPaths(
			"WriteOnlyPaths", profile.Filesystem.WriteOnlyPaths,
		)...)
		errs = append(errs, validateEmptyPaths(
			"ReadWritePaths", profile.Filesystem.ReadWritePaths,
		)...)
	}

	return errors.Join(errs...)
}

func validateFilesystemPaths(rules *FilesystemRules) error {
	seen := make(map[string]string)

	var errs []error

	for _, path := range rules.ReadOnlyPaths {
		seen[path] = "ReadOnlyPaths"
	}

	for _, path := range rules.WriteOnlyPaths {
		if category, ok := seen[path]; ok {
			errs = append(errs, fmt.Errorf(
				"path %q in both %s and WriteOnlyPaths: %w",
				path, category, ErrDuplicatePath,
			))
		}

		seen[path] = "WriteOnlyPaths"
	}

	for _, path := range rules.ReadWritePaths {
		if category, ok := seen[path]; ok {
			errs = append(errs, fmt.Errorf(
				"path %q in both %s and ReadWritePaths: %w",
				path, category, ErrDuplicatePath,
			))
		}
	}

	return errors.Join(errs...)
}
