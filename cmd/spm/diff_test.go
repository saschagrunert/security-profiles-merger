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

	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

func TestDiffSeccompEqual(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (equal)", code)
	}

	var diff seccomp.ProfileDiff

	unmarshalOutput(t, stdout, &diff)

	if !diff.Equal {
		t.Error("expected equal profiles")
	}
}

func TestDiffSeccompDifferent(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d (different)", code, exitDiff)
	}

	var diff seccomp.ProfileDiff

	unmarshalOutput(t, stdout, &diff)

	if diff.Equal {
		t.Error("expected different profiles")
	}

	if diff.Syscalls == nil {
		t.Fatal("expected syscall diff")
	}
}

func TestDiffSeccompHuman(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, flagFormat, formatHuman, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	if !strings.Contains(stdout, "Diff{") {
		t.Errorf("expected Diff{...} output, got: %s", stdout)
	}
}

func TestDiffAppArmor(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	fileB := writeTemp(t, apparmorJSON(t, "CHOWN"))

	code, _, _ := runCapture(t, []string{
		cmdDiff, flagType, typeAppArmor, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d (different)", code, exitDiff)
	}
}

func TestDiffLandlock(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, landlockJSON(t, "read_file"))
	fileB := writeTemp(t, landlockJSON(t, "write_file"))

	code, _, _ := runCapture(t, []string{
		cmdDiff, flagType, typeLandlock, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d (different)", code, exitDiff)
	}
}

func TestDiffMissingType(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdDiff, fileA, fileB,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "--type") {
		t.Errorf("stderr should mention --type, got: %s", stderr)
	}
}

func TestDiffUnknownType(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, testBogus, fileA, fileB,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown type") {
		t.Errorf("stderr should mention unknown type, got: %s", stderr)
	}
}

func TestDiffWrongFileCount(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "exactly 2") {
		t.Errorf("stderr should mention 2 files, got: %s", stderr)
	}
}

func TestDiffStdinArray(t *testing.T) {
	t.Parallel()

	profileA := seccompJSON(t, testSyscallRead)
	profileB := seccompJSON(t, "write")
	stdin := strings.NewReader("[" + profileA + "," + profileB + "]")

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp,
	}, stdin)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	var diff seccomp.ProfileDiff

	unmarshalOutput(t, stdout, &diff)

	if diff.Equal {
		t.Error("expected different profiles")
	}
}

func TestDiffStdinWrongCount(t *testing.T) {
	t.Parallel()

	profileA := seccompJSON(t, testSyscallRead)
	stdin := strings.NewReader("[" + profileA + "]")

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp,
	}, stdin)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "exactly 2") {
		t.Errorf("stderr should mention 2 profiles, got: %s", stderr)
	}
}

func TestDiffInvalidJSON(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, "not valid json")
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA, fileB,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "error") {
		t.Errorf("stderr should contain error, got: %s", stderr)
	}
}

func TestDiffThreeFiles(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileC := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA, fileB, fileC,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "exactly 2") {
		t.Errorf("stderr should mention 2 files, got: %s", stderr)
	}
}

func TestDiffUnknownFormat(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, flagFormat, testBogus,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown format") {
		t.Errorf("stderr should mention unknown format, got: %s", stderr)
	}
}
