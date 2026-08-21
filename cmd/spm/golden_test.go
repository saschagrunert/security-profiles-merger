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
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool(
	"update",
	false,
	"update golden files",
)

func TestGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		stdinFile string
		wantCode  int
		golden    string
	}{
		{
			name: "diff seccomp human",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				flagFormat,
				formatHuman,
				testdataSeccompA,
				testdataSeccompB,
			},
			stdinFile: "",
			wantCode:  exitDiff,
			golden:    "testdata/diff_seccomp_human.golden",
		},
		{
			name: "diff apparmor human",
			args: []string{
				cmdDiff,
				flagType,
				typeAppArmor,
				flagFormat,
				formatHuman,
				"testdata/apparmor_a.json",
				"testdata/apparmor_b.json",
			},
			stdinFile: "",
			wantCode:  exitDiff,
			golden:    "testdata/diff_apparmor_human.golden",
		},
		{
			name: "diff landlock human",
			args: []string{
				cmdDiff,
				flagType,
				typeLandlock,
				flagFormat,
				formatHuman,
				"testdata/landlock_a.json",
				"testdata/landlock_b.json",
			},
			stdinFile: "",
			wantCode:  exitDiff,
			golden:    "testdata/diff_landlock_human.golden",
		},
		{
			name: "diff seccomp json",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				testdataSeccompA,
				testdataSeccompB,
			},
			stdinFile: "",
			wantCode:  exitDiff,
			golden:    "testdata/diff_seccomp_json.golden",
		},
		{
			name: "diff seccomp equal",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				flagFormat,
				formatHuman,
				testdataSeccompA,
				testdataSeccompA,
			},
			stdinFile: "",
			wantCode:  0,
			golden:    "testdata/diff_seccomp_equal.golden",
		},
		{
			name: "merge seccomp intersect",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				testdataSeccompA,
				testdataSeccompB,
			},
			stdinFile: "",
			wantCode:  0,
			golden:    "testdata/merge_seccomp_intersect.golden",
		},
		{
			name: "merge apparmor union",
			args: []string{
				cmdMerge,
				flagType,
				typeAppArmor,
				flagStrategy,
				strategyUnion,
				"testdata/apparmor_a.json",
				"testdata/apparmor_b.json",
			},
			stdinFile: "",
			wantCode:  0,
			golden:    "testdata/merge_apparmor_union.golden",
		},
		{
			name: "merge landlock intersect human",
			args: []string{
				cmdMerge,
				flagType,
				typeLandlock,
				flagStrategy,
				strategyIntersect,
				flagFormat,
				formatHuman,
				"testdata/landlock_a.json",
				"testdata/landlock_b.json",
			},
			stdinFile: "",
			wantCode:  0,
			golden:    "testdata/merge_landlock_intersect_human.golden",
		},
		{
			name: "merge seccomp union stdin",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyUnion,
			},
			stdinFile: "testdata/seccomp_stdin.json",
			wantCode:  0,
			golden:    "testdata/merge_seccomp_union_stdin.golden",
		},
		{
			name: "validate seccomp",
			args: []string{
				cmdValidate,
				flagType,
				typeSeccomp,
				testdataSeccompA,
			},
			stdinFile: "",
			wantCode:  0,
			golden:    "testdata/validate_seccomp.golden",
		},
		{
			name: "validate apparmor human",
			args: []string{
				cmdValidate,
				flagType,
				typeAppArmor,
				flagFormat,
				formatHuman,
				"testdata/apparmor_a.json",
			},
			stdinFile: "",
			wantCode:  0,
			golden:    "testdata/validate_apparmor_human.golden",
		},
		{
			name: "validate landlock",
			args: []string{
				cmdValidate,
				flagType,
				typeLandlock,
				"testdata/landlock_a.json",
			},
			stdinFile: "",
			wantCode:  0,
			golden:    "testdata/validate_landlock.golden",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var stdin io.Reader

			if testCase.stdinFile != "" {
				data, err := os.ReadFile(testCase.stdinFile)
				if err != nil {
					t.Fatalf("reading stdin file: %v", err)
				}

				stdin = bytes.NewReader(data)
			}

			code, stdout, _ := runCapture(t, testCase.args, stdin)
			if code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d", code, testCase.wantCode)
			}

			goldenPath := testCase.golden
			if *update {
				err := os.MkdirAll(filepath.Dir(goldenPath), 0o750)
				if err != nil {
					t.Fatal(err)
				}

				err = os.WriteFile(goldenPath, []byte(stdout), 0o600)
				if err != nil {
					t.Fatal(err)
				}
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("reading golden file (run with -update to create): %v", err)
			}

			if stdout != string(want) {
				t.Errorf("output mismatch (-want +got):\nwant:\n%s\ngot:\n%s", string(want), stdout)
			}
		})
	}
}
