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

package landlock

import (
	"errors"
	"fmt"
)

var (
	// ErrUnknownRight is returned when a profile contains an unrecognized
	// access right value.
	ErrUnknownRight = errors.New("unknown access right")

	// ErrDuplicateRule is returned when a profile contains multiple rules
	// for the same path or port.
	ErrDuplicateRule = errors.New("duplicate rule")

	// ErrEmptyPath is returned when a path rule has an empty path string.
	ErrEmptyPath = errors.New("empty path in path rule")

	// ErrUnhandledRight is returned when a rule grants an access right
	// that is not listed in the profile's handled access set.
	ErrUnhandledRight = errors.New("rule grants unhandled access right")

	// ErrDuplicateRight is returned when the same access right appears
	// more than once in a handled set or rule.
	ErrDuplicateRight = errors.New("duplicate access right")
)

// Validate checks that a Landlock profile contains only known access
// right values. Unknown values pass through merge silently, which may
// produce unexpected results at enforcement time. All validation failures
// are collected and returned together.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	err := validateRights("HandledAccessFS", profile.HandledAccessFS, isKnownFSRight)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateRights("HandledAccessNet", profile.HandledAccessNet, isKnownNetRight)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicateRights("HandledAccessFS", profile.HandledAccessFS)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicateRights("HandledAccessNet", profile.HandledAccessNet)
	if err != nil {
		errs = append(errs, err)
	}

	errs = append(errs, validatePathRules(profile.PathRules)...)
	errs = append(errs, validateNetRules(profile.NetRules)...)

	err = validateDuplicatePaths(profile.PathRules)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicatePorts(profile.NetRules)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func validateRights[T ~string](
	context string, rights []T, known func(T) bool,
) error {
	var errs []error

	for _, right := range rights {
		if !known(right) {
			errs = append(errs, fmt.Errorf("%s: %w %q", context, ErrUnknownRight, right))
		}
	}

	return errors.Join(errs...)
}

// validateEmptyPathsBeforeNormalize catches empty paths before
// filepath.Clean("") turns them into ".", which would bypass Validate.
func validateEmptyPathsBeforeNormalize(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	for idx, rule := range profile.PathRules {
		if rule.Path == "" {
			errs = append(errs, fmt.Errorf("PathRules[%d]: %w", idx, ErrEmptyPath))
		}
	}

	return errors.Join(errs...)
}

// validatePathRules checks path rules for empty paths, unknown rights, and
// duplicate rights. The empty-path check here covers direct Validate callers;
// foldProfiles also runs validateEmptyPathsBeforeNormalize to catch empty
// paths before filepath.Clean turns them into ".".
func validatePathRules(rules []PathRule) []error {
	var errs []error

	for idx, rule := range rules {
		if rule.Path == "" {
			errs = append(errs, fmt.Errorf("PathRules[%d]: %w", idx, ErrEmptyPath))
		}

		context := fmt.Sprintf("PathRules[%d]", idx)

		err := validateRights(context, rule.AccessFS, isKnownFSRight)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicateRights(context, rule.AccessFS)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func validateNetRules(rules []NetRule) []error {
	var errs []error

	for idx, rule := range rules {
		context := fmt.Sprintf("NetRules[%d]", idx)

		err := validateRights(context, rule.AccessNet, isKnownNetRight)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicateRights(context, rule.AccessNet)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func isKnownFSRight(right FSAccessRight) bool {
	switch right {
	case FSAccessExecute,
		FSAccessWriteFile,
		FSAccessReadFile,
		FSAccessReadDir,
		FSAccessRemoveDir,
		FSAccessRemoveFile,
		FSAccessMakeChar,
		FSAccessMakeDir,
		FSAccessMakeReg,
		FSAccessMakeSock,
		FSAccessMakeFIFO,
		FSAccessMakeSym,
		FSAccessMakeBlock,
		FSAccessRefer,
		FSAccessTruncate,
		FSAccessIOCTLDev,
		FSAccessResolveUnix:
		return true
	default:
		return false
	}
}

func isKnownNetRight(right NetAccessRight) bool {
	switch right {
	case NetAccessBindTCP, NetAccessConnectTCP,
		NetAccessBindUDP, NetAccessConnectSendUDP:
		return true
	default:
		return false
	}
}

func validateDuplicatePaths(rules []PathRule) error {
	seen := make(map[string]struct{}, len(rules))

	var errs []error

	for _, rule := range rules {
		if _, ok := seen[rule.Path]; ok {
			errs = append(errs, fmt.Errorf("path %q: %w", rule.Path, ErrDuplicateRule))
		}

		seen[rule.Path] = struct{}{}
	}

	return errors.Join(errs...)
}

// ValidateStrict performs all checks from Validate and additionally verifies
// that every rule's access rights are a subset of the corresponding handled
// access set. In Landlock semantics, unhandled rights are implicitly allowed
// everywhere, so granting an unhandled right in a rule is a no-op and likely
// a configuration error.
//
// Merge results may legitimately contain unhandled rights in rules (for
// example, union intersects the handled sets while preserving rules from both
// inputs). Use Validate for merge inputs and ValidateStrict for
// user-authored profiles.
func ValidateStrict(profile *Profile) error {
	err := Validate(profile)
	if err != nil {
		return err
	}

	var errs []error

	handledFS := toSet(profile.HandledAccessFS)
	handledNet := toSet(profile.HandledAccessNet)

	for idx, rule := range profile.PathRules {
		e := validateHandled(
			fmt.Sprintf("PathRules[%d]", idx), rule.AccessFS, handledFS,
		)
		if e != nil {
			errs = append(errs, e)
		}
	}

	for idx, rule := range profile.NetRules {
		e := validateHandled(
			fmt.Sprintf("NetRules[%d]", idx), rule.AccessNet, handledNet,
		)
		if e != nil {
			errs = append(errs, e)
		}
	}

	return errors.Join(errs...)
}

func validateHandled[T ~string](
	context string, rights []T, handled map[T]struct{},
) error {
	var errs []error

	for _, right := range rights {
		if _, ok := handled[right]; !ok {
			errs = append(errs, fmt.Errorf(
				"%s: right %q: %w", context, right, ErrUnhandledRight,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateRights[T ~string](context string, rights []T) error {
	seen := make(map[T]struct{}, len(rights))

	var errs []error

	for _, right := range rights {
		if _, ok := seen[right]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: right %q: %w", context, right, ErrDuplicateRight,
			))
		}

		seen[right] = struct{}{}
	}

	return errors.Join(errs...)
}

func validateDuplicatePorts(rules []NetRule) error {
	seen := make(map[uint16]struct{}, len(rules))

	var errs []error

	for _, rule := range rules {
		if _, ok := seen[rule.Port]; ok {
			errs = append(errs, fmt.Errorf("port %d: %w", rule.Port, ErrDuplicateRule))
		}

		seen[rule.Port] = struct{}{}
	}

	return errors.Join(errs...)
}
