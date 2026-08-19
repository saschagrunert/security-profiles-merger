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

package main

import (
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
	"github.com/saschagrunert/security-profiles-merger/landlock"
)

func TestValidateHelp(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{cmdValidate, flagHelp}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "Usage: spm validate") {
		t.Errorf("stderr should contain usage header, got: %s", stderr)
	}

	if !strings.Contains(stderr, "[files...]") {
		t.Errorf("stderr should mention files, got: %s", stderr)
	}
}

func TestValidateEmptyStdin(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp,
	}, strings.NewReader(""))

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "no input") {
		t.Errorf("stderr = %q, want mention of no input", stderr)
	}
}

func TestValidateUnknownFormat(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagFormat, "xml",
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown format") {
		t.Errorf("stderr = %q, want mention of unknown format", stderr)
	}
}

func TestValidateEmptyArray(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp,
	}, strings.NewReader("[]"))

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "no input") {
		t.Errorf("stderr = %q, want mention of no input", stderr)
	}
}

func TestValidateInvalidJSONSeccomp(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, "not json")
	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "error:") {
		t.Errorf("stderr = %q, want error message", stderr)
	}
}

func TestValidateInvalidJSONAppArmor(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, "not json")
	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "error:") {
		t.Errorf("stderr = %q, want error message", stderr)
	}
}

func TestValidateInvalidJSONLandlock(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, "not json")
	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "error:") {
		t.Errorf("stderr = %q, want error message", stderr)
	}
}

func TestValidateLandlockInvalid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"read_file"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: testEtcPath, AccessFS: []landlock.FSAccessRight{"read_file"}},
			{Path: testEtcPath, AccessFS: []landlock.FSAccessRight{"write_file"}},
		},
		NetRules: nil,
	}

	file := writeTemp(t, marshal(t, profile))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "duplicate") {
		t.Errorf("stderr = %q, want mention of duplicate", stderr)
	}
}

func TestValidateMissingType(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{cmdValidate}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "--type is required") {
		t.Errorf("stderr = %q, want mention of required flag", stderr)
	}
}

func TestValidateUnknownType(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, testBogus,
	}, strings.NewReader("{}"))

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown type") {
		t.Errorf("stderr = %q, want mention of unknown type", stderr)
	}
}

func TestValidateSeccompValid(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if result.DefaultAction != specs.ActErrno {
		t.Errorf("expected SCMP_ACT_ERRNO, got %v", result.DefaultAction)
	}
}

func TestValidateSeccompStrictDuplicate(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{testSyscallRead}, Action: specs.ActAllow},
			{Names: []string{testSyscallRead}, Action: specs.ActErrno},
		},
	}

	file := writeTemp(t, marshal(t, profile))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagStrict, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "duplicate") {
		t.Errorf("stderr = %q, want mention of duplicate", stderr)
	}
}

func TestValidateAppArmorValid(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 1 {
		t.Errorf("expected 1 capability, got %v", result)
	}
}

func TestValidateAppArmorHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, flagFormat, formatHuman, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "caps:") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestValidateAppArmorStrict(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, _, _ := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, flagStrict, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestValidateAppArmorInvalid(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{testEtcPath},
			WriteOnlyPaths: []string{testEtcPath},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	file := writeTemp(t, marshal(t, profile))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "duplicate path") {
		t.Errorf("stderr = %q, want mention of duplicate path", stderr)
	}
}

func TestValidateLandlockValid(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.HandledAccessFS) != 1 {
		t.Errorf("expected 1 handled FS right, got %d", len(result.HandledAccessFS))
	}
}

func TestValidateLandlockStrict(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, landlockJSON(t, "read_file"))

	code, _, _ := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, flagStrict, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestValidateLandlockHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, flagFormat, formatHuman, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "read_file") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestValidateHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagFormat, formatHuman, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "Profile{") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestValidateMultipleProfiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead))
	p2 := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result []specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(result))
	}
}

func TestValidateMultipleProfilesHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead))
	p2 := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "Profile{") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestValidateSeccompStrict(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagStrict, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}
