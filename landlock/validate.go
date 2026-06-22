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

// ErrUnknownRight is returned when a profile contains an unrecognized
// access right value.
var ErrUnknownRight = errors.New("unknown access right")

// Validate checks that a Landlock profile contains only known access
// right values. Unknown values pass through merge silently, which may
// produce unexpected results at enforcement time.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	err := validateRights("HandledAccessFS", profile.HandledAccessFS, isKnownFSRight)
	if err != nil {
		return err
	}

	err = validateRights("HandledAccessNet", profile.HandledAccessNet, isKnownNetRight)
	if err != nil {
		return err
	}

	for idx, rule := range profile.PathRules {
		err := validateRights(fmt.Sprintf("PathRules[%d]", idx), rule.AccessFS, isKnownFSRight)
		if err != nil {
			return err
		}
	}

	for idx, rule := range profile.NetRules {
		err := validateRights(fmt.Sprintf("NetRules[%d]", idx), rule.AccessNet, isKnownNetRight)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateRights[T ~string](
	context string, rights []T, known func(T) bool,
) error {
	for _, right := range rights {
		if !known(right) {
			return fmt.Errorf("%s: %w %q", context, ErrUnknownRight, right)
		}
	}

	return nil
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
		FSAccessIOCTLDev:
		return true
	default:
		return false
	}
}

func isKnownNetRight(right NetAccessRight) bool {
	switch right {
	case NetAccessBindTCP, NetAccessConnectTCP:
		return true
	default:
		return false
	}
}
