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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
	"github.com/saschagrunert/security-profiles-merger/landlock"
	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

func TestMergeHelp(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{cmdMerge, flagHelp}, nil)

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

func TestMergeSeccompInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(seccompJSON(t, testSyscallRead))}

	code := mergeProfiles(
		data, testBogus, formatJSON,
		seccomp.Intersect, seccomp.Union, seccomp.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeSeccompNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		nil, strategyIntersect, formatJSON,
		seccomp.Intersect, seccomp.Union, seccomp.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeAppArmorInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(apparmorJSON(t, "NET_ADMIN"))}

	code := mergeProfiles(
		data, testBogus, formatJSON,
		apparmor.Intersect, apparmor.Union, apparmor.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeAppArmorNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		nil, strategyIntersect, formatJSON,
		apparmor.Intersect, apparmor.Union, apparmor.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeLandlockInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(landlockJSON(t, "read_file"))}

	code := mergeProfiles(
		data, testBogus, formatJSON,
		landlock.Intersect, landlock.Union, landlock.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeLandlockNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		nil, strategyUnion, formatJSON,
		landlock.Intersect, landlock.Union, landlock.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

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

func TestMergeStdinTooLarge(t *testing.T) {
	t.Parallel()

	large := bytes.NewReader(make([]byte, maxStdinSize+1))

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
	}, large)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "exceeds") {
		t.Errorf("stderr should mention size exceeded, got: %s", stderr)
	}
}
