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
	"errors"
	"strings"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := apparmor.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: []string{pathVarLog},
		},
		Network: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEmpty(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error for empty profile: %v", err)
	}
}

func TestValidateDuplicateReadOnlyAndWriteOnly(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in ReadOnly and WriteOnly")
	}
}

func TestValidateDuplicateReadOnlyAndReadWrite(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathEtcConfig},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in ReadOnly and ReadWrite")
	}
}

func TestValidateDuplicateWriteOnlyAndReadWrite(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in WriteOnly and ReadWrite")
	}
}

func TestValidateMultipleDuplicates(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathTmp},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for multiple duplicate paths")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePath) {
		t.Errorf("expected ErrDuplicatePath, got: %v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, pathEtcConfig) {
		t.Errorf("error should mention %s: %v", pathEtcConfig, err)
	}

	if !strings.Contains(msg, pathTmp) {
		t.Errorf("error should mention %s: %v", pathTmp, err)
	}
}

func TestValidateEmptyPathInReadOnly(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{""},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty path")
	}

	if !errors.Is(err, apparmor.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestValidateEmptyPathInExecutables(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/bin/bash", ""},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty executable path")
	}

	if !errors.Is(err, apparmor.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestValidateDuplicatePathInCategory(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path within category")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf(
			"expected ErrDuplicatePathInCategory, got: %v", err,
		)
	}
}

func TestValidateDuplicatePathInWriteOnlyCategory(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathTmp, pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in WriteOnlyPaths")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf(
			"expected ErrDuplicatePathInCategory, got: %v", err,
		)
	}
}

func TestValidateDuplicatePathInReadWriteCategory(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathVarLog, pathVarLog},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in ReadWritePaths")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf(
			"expected ErrDuplicatePathInCategory, got: %v", err,
		)
	}
}

func TestValidateDuplicateCapability(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{
				capNetAdmin, capSysTime, capNetAdmin,
			},
		},
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate capability")
	}

	if !errors.Is(err, apparmor.ErrDuplicateCapability) {
		t.Errorf("expected ErrDuplicateCapability, got: %v", err)
	}

	if !strings.Contains(err.Error(), capNetAdmin) {
		t.Errorf(
			"error should mention %s: %v", capNetAdmin, err,
		)
	}
}
