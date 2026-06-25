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
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
	"github.com/saschagrunert/security-profiles-merger/landlock"
)

const (
	flagType     = "--type"
	flagStrategy = "--strategy"
	flagFormat   = "--format"

	flagStrict = "--strict"

	testBogus       = "bogus"
	testEtcPath     = "/etc"
	testSyscallRead = "read"
)

func TestNoArgs(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, nil, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr should contain usage, got: %s", stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{testBogus}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr should mention unknown command, got: %s", stderr)
	}
}

func TestMergeHelp(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{cmdMerge, "--help"}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "Usage: spm merge") {
		t.Errorf("stderr should contain usage header, got: %s", stderr)
	}

	if !strings.Contains(stderr, "[files...]") {
		t.Errorf("stderr should mention files, got: %s", stderr)
	}
}

func TestValidateHelp(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{cmdValidate, "--help"}, nil)

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

func TestMergeEmptyStdin(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
	}, strings.NewReader(""))

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "no input") {
		t.Errorf("stderr = %q, want mention of no input", stderr)
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

func TestMergeSeccompInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(seccompJSON(t, testSyscallRead))}

	code := mergeSeccomp(data, testBogus, formatJSON, &bytes.Buffer{}, &bytes.Buffer{})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeSeccompNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeSeccomp(nil, strategyIntersect, formatJSON, &bytes.Buffer{}, &bytes.Buffer{})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeAppArmorInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(apparmorJSON(t, "NET_ADMIN"))}

	code := mergeAppArmor(data, testBogus, formatJSON, &bytes.Buffer{}, &bytes.Buffer{})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeAppArmorNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeAppArmor(nil, strategyIntersect, formatJSON, &bytes.Buffer{}, &bytes.Buffer{})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeLandlockInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(landlockJSON(t, "read_file"))}

	code := mergeLandlock(data, testBogus, formatJSON, &bytes.Buffer{}, &bytes.Buffer{})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeLandlockNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeLandlock(nil, strategyUnion, formatJSON, &bytes.Buffer{}, &bytes.Buffer{})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeNilStdin(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "no input") {
		t.Errorf("stderr = %q, want mention of no input", stderr)
	}
}

func TestMergeEmptyArray(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
	}, strings.NewReader("[]"))

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "no input") {
		t.Errorf("stderr = %q, want mention of no input", stderr)
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

func TestMergeMissingFlags(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{cmdMerge}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "--type and --strategy are required") {
		t.Errorf("stderr = %q, want mention of required flags", stderr)
	}
}

func TestMergeMissingStrategy(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "--type and --strategy are required") {
		t.Errorf("stderr = %q, want mention of required flags", stderr)
	}
}

func TestMergeUnknownStrategy(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, testBogus,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown strategy") {
		t.Errorf("stderr = %q, want mention of unknown strategy", stderr)
	}
}

func TestMergeUnknownType(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, testBogus, flagStrategy, strategyIntersect,
	}, strings.NewReader("[{}]"))

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown type") {
		t.Errorf("stderr = %q, want mention of unknown type", stderr)
	}
}

func TestMergeUnknownFormat(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		flagFormat, "xml",
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown format") {
		t.Errorf("stderr = %q, want mention of unknown format", stderr)
	}
}

func TestMergeNonexistentFile(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		"/nonexistent/profile.json",
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "error:") {
		t.Errorf("stderr = %q, want error message", stderr)
	}
}

func TestMergeInvalidJSON(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, "not valid json")
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "error:") {
		t.Errorf("stderr = %q, want error message", stderr)
	}
}

func TestMergeInvalidJSONAppArmor(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, "not valid json")
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "error:") {
		t.Errorf("stderr = %q, want error message", stderr)
	}
}

func TestMergeInvalidJSONLandlock(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, "not valid json")
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyIntersect, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "error:") {
		t.Errorf("stderr = %q, want error message", stderr)
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

func TestMergeSeccompIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead, "write"))
	p2 := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 || result.Syscalls[0].Names[0] != testSyscallRead {
		t.Errorf("expected only read syscall, got %v", result.Syscalls)
	}
}

func TestMergeSeccompUnionStdin(t *testing.T) {
	t.Parallel()

	input := "[" + seccompJSON(t, testSyscallRead) + "," +
		seccompJSON(t, "write") + "]"

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
	}, strings.NewReader(input))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 2 {
		t.Errorf("expected 2 syscalls, got %d", len(result.Syscalls))
	}
}

func TestMergeSeccompHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead))
	p2 := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "Profile{") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeAppArmorUnionFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	p2 := writeTemp(t, apparmorJSON(t, "SYS_TIME"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %v", result)
	}
}

func TestMergeAppArmorIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN", "SYS_TIME"))
	p2 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect, p1, p2,
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

func TestMergeLandlockIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file", "write_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyIntersect, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}

	if len(result.PathRules[0].AccessFS) != 1 ||
		result.PathRules[0].AccessFS[0] != landlock.FSAccessReadFile {
		t.Errorf("expected read_file only, got %v", result.PathRules[0].AccessFS)
	}
}

func TestMergeLandlockUnionFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file"))
	p2 := writeTemp(t, landlockJSON(t, "write_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}
}

func TestMergeAppArmorHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	p2 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "caps:") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeLandlockHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "read_file") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeStdinDash(t *testing.T) {
	t.Parallel()

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, "-",
	}, strings.NewReader("["+
		seccompJSON(t, testSyscallRead)+","+
		seccompJSON(t, testSyscallRead)+"]"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(result.Syscalls))
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

// Helpers.

//nolint:gocritic // unnamedResult conflicts with nonamedreturns
func runCapture(
	t *testing.T,
	args []string,
	stdin io.Reader,
) (int, string, string) {
	t.Helper()

	var stdoutBuf, stderrBuf bytes.Buffer

	code := run(args, stdin, &stdoutBuf, &stderrBuf)

	return code, stdoutBuf.String(), stderrBuf.String()
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()

	file := filepath.Join(t.TempDir(), "profile.json")

	err := os.WriteFile(file, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	return file
}

func marshal(t *testing.T, v any) string {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	return string(data)
}

func unmarshalOutput(t *testing.T, data string, v any) {
	t.Helper()

	err := json.Unmarshal([]byte(data), v)
	if err != nil {
		t.Fatalf("unmarshaling output %q: %v", data, err)
	}
}

func seccompJSON(t *testing.T, syscalls ...string) string {
	t.Helper()

	entries := make([]specs.LinuxSyscall, len(syscalls))
	for idx, name := range syscalls {
		entries[idx] = specs.LinuxSyscall{
			Names:  []string{name},
			Action: specs.ActAllow,
		}
	}

	return marshal(t, &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      entries,
	})
}

func apparmorJSON(t *testing.T, caps ...string) string {
	t.Helper()

	return marshal(t, &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: caps,
		},
	})
}

func landlockJSON(t *testing.T, rights ...string) string {
	t.Helper()

	fsRights := make([]landlock.FSAccessRight, len(rights))
	for idx, right := range rights {
		fsRights[idx] = landlock.FSAccessRight(right)
	}

	return marshal(t, &landlock.Profile{
		HandledAccessFS:  fsRights,
		HandledAccessNet: nil,
		PathRules: []landlock.PathRule{{
			Path:     testEtcPath,
			AccessFS: fsRights,
		}},
		NetRules: nil,
	})
}
