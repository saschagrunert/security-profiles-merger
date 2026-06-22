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
	"slices"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
)

const (
	globBinStar    = "/bin/*"
	globUsrLib     = "/usr/lib/**"
	globTmpFQO     = "/tmp/f?o"
	globEtcBraces  = "/etc/{passwd,shadow}"
	globProcStatus = "/proc/*/status"
	globUsrLibSO   = "/usr/lib/**/*.so"
	globDataStar   = "/data/*"

	pathBinLs    = "/bin/ls"
	pathDataFile = "/data/file"
)

func TestUnionGlobInvalidUTF8(t *testing.T) {
	t.Parallel()

	invalid := "/bin/\xac"

	assertGlobUnion(
		t,
		[]string{pathBinLs},
		[]string{invalid},
		[]string{pathBinLs, invalid},
	)
}

func TestUnionGlobStar(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "matches within directory",
			left:  []string{globBinStar},
			right: []string{pathBinLs},
			want:  []string{globBinStar},
		},
		{
			name:  "does not match across directories",
			left:  []string{globBinStar},
			right: []string{"/bin/sub/dir"},
			want:  []string{globBinStar, "/bin/sub/dir"},
		},
		{
			name:  "double star matches across directories",
			left:  []string{globUsrLib},
			right: []string{"/usr/lib/x86_64/libc.so"},
			want:  []string{globUsrLib},
		},
		{
			name:  "double star matches empty suffix",
			left:  []string{globUsrLib},
			right: []string{"/usr/lib/"},
			want:  []string{globUsrLib},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobQuestionMark(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "matches single char",
			left:  []string{globTmpFQO},
			right: []string{"/tmp/foo"},
			want:  []string{globTmpFQO},
		},
		{
			name:  "does not match extra chars",
			left:  []string{globTmpFQO},
			right: []string{"/tmp/fooo"},
			want:  []string{globTmpFQO, "/tmp/fooo"},
		},
		{
			name:  "does not match slash",
			left:  []string{globTmpFQO},
			right: []string{"/tmp/f/o"},
			want:  []string{"/tmp/f/o", globTmpFQO},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobBraces(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "matches alternatives",
			left:  []string{globEtcBraces},
			right: []string{"/etc/passwd", "/etc/shadow"},
			want:  []string{globEtcBraces},
		},
		{
			name:  "does not match other values",
			left:  []string{globEtcBraces},
			right: []string{"/etc/group"},
			want:  []string{"/etc/group", globEtcBraces},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobCombined(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "star in path component",
			left:  []string{globProcStatus},
			right: []string{"/proc/1/status", "/proc/self/status"},
			want:  []string{globProcStatus},
		},
		{
			name:  "star does not cross directories",
			left:  []string{globProcStatus},
			right: []string{"/proc/1/2/status"},
			want:  []string{globProcStatus, "/proc/1/2/status"},
		},
		{
			name:  "double star with suffix matches nested",
			left:  []string{globUsrLibSO},
			right: []string{"/usr/lib/x86_64/libc.so"},
			want:  []string{globUsrLibSO},
		},
		{
			name:  "double star slash requires dir level",
			left:  []string{globUsrLibSO},
			right: []string{pathLibC},
			want:  []string{globUsrLibSO, pathLibC},
		},
		{
			name:  "glob subsumes library paths",
			left:  []string{globUsrLib},
			right: []string{pathLibC, "/opt/lib/custom.so"},
			want:  []string{"/opt/lib/custom.so", globUsrLib},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobLiteral(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "dot matches literal dot only",
			left:  []string{"/etc/config.d"},
			right: []string{"/etc/configXd"},
			want:  []string{"/etc/config.d", "/etc/configXd"},
		},
		{
			name:  "exact match deduplicates",
			left:  []string{pathBinBash},
			right: []string{pathBinBash},
			want:  []string{pathBinBash},
		},
		{
			name:  "does not match suffix",
			left:  []string{pathBinBash},
			right: []string{"/usr/bin/bash2"},
			want:  []string{pathBinBash, "/usr/bin/bash2"},
		},
		{
			name:  "brackets are escaped",
			left:  []string{"/etc/config[1]"},
			right: []string{"/etc/config1"},
			want:  []string{"/etc/config1", "/etc/config[1]"},
		},
		{
			name:  "plus sign is escaped",
			left:  []string{"/opt/c++/bin"},
			right: []string{"/opt/cXX/bin"},
			want:  []string{"/opt/c++/bin", "/opt/cXX/bin"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionFilesystemGlobPromotion(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  apparmor.FilesystemRules
		right apparmor.FilesystemRules
		want  apparmor.FilesystemRules
	}{
		{
			name: "read-only promoted to read-write",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{globProcStatus},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: []string{"/proc/1/status"},
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: nil,
				ReadWritePaths: []string{globProcStatus},
			},
		},
		{
			name: "write-only promoted to read-write",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: []string{globDataStar},
				ReadWritePaths: nil,
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathDataFile},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: nil,
				ReadWritePaths: []string{globDataStar},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertFilesystemGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionFilesystemGlobSubsume(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{"/var/log/**"},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/var/log/syslog"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{"/var/log/**"},
		},
	)
}

func TestUnionFilesystemGlobNew(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/r/*"},
			WriteOnlyPaths: []string{"/w/*"},
			ReadWritePaths: []string{"/rw/*"},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/r2/foo"},
			WriteOnlyPaths: []string{"/w2/bar"},
			ReadWritePaths: []string{"/rw2/baz"},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/r/*", "/r2/foo"},
			WriteOnlyPaths: []string{"/w/*", "/w2/bar"},
			ReadWritePaths: []string{"/rw/*", "/rw2/baz"},
		},
	)
}

func TestUnionGlobReverseSubsumption(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "right glob subsumes left literal",
			left:  []string{pathLibC},
			right: []string{globUsrLib},
			want:  []string{globUsrLib},
		},
		{
			name:  "right glob subsumes multiple left literals",
			left:  []string{pathLibC, "/usr/lib/libm.so"},
			right: []string{globUsrLib},
			want:  []string{globUsrLib},
		},
		{
			name:  "right star subsumes left literals in same dir",
			left:  []string{pathBinLs, "/bin/cat"},
			right: []string{globBinStar},
			want:  []string{globBinStar},
		},
		{
			name:  "right glob keeps non-matching left entries",
			left:  []string{"/opt/bin/tool", pathBinLs},
			right: []string{globBinStar},
			want:  []string{globBinStar, "/opt/bin/tool"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobOverlapping(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "double star coexists with single star",
			left:  []string{"/usr/lib/*"},
			right: []string{globUsrLib},
			want:  []string{"/usr/lib/*", globUsrLib},
		},
		{
			name:  "single star not subsumed by different double star",
			left:  []string{"/bin/*"},
			right: []string{globUsrLib},
			want:  []string{"/bin/*", globUsrLib},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobThreeWay(t *testing.T) {
	t.Parallel()

	first := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinLs, "/bin/cat"},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	second := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{globBinStar},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	third := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/bin/sh", "/opt/tool"},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{globBinStar, "/opt/tool"}
	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf("got %v, want %v", result.Executable.AllowedExecutables, want)
	}
}

func TestUnionFilesystemRWPromotesFromReadSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathDataFile},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestUnionFilesystemRWPromotesFromWriteSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathDataFile},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestUnionFilesystemRWAlreadyInRWSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
	)
}

func TestUnionFilesystemWriteAlreadyInRWSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathDataFile},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
	)
}

func TestUnionGlobDuplicateGlob(t *testing.T) {
	t.Parallel()

	assertGlobUnion(
		t,
		[]string{globBinStar, pathLibC},
		[]string{globBinStar},
		[]string{globBinStar, pathLibC},
	)
}

func TestUnionFilesystemBroaderRightGlobPromotion(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathDataFile},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{globDataStar},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
	)
}

func assertGlobUnion(t *testing.T, left, right, want []string) {
	t.Helper()

	leftProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: left,
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	rightProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: right,
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(leftProfile, rightProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf(
			"got %v, want %v",
			result.Executable.AllowedExecutables, want,
		)
	}
}

func assertFilesystemGlobUnion(
	t *testing.T,
	left, right, want apparmor.FilesystemRules,
) {
	t.Helper()

	leftProfile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  slices.Clone(left.ReadOnlyPaths),
			WriteOnlyPaths: slices.Clone(left.WriteOnlyPaths),
			ReadWritePaths: slices.Clone(left.ReadWritePaths),
		},
		Network:      nil,
		Capabilities: nil,
	}

	rightProfile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  slices.Clone(right.ReadOnlyPaths),
			WriteOnlyPaths: slices.Clone(right.WriteOnlyPaths),
			ReadWritePaths: slices.Clone(right.ReadWritePaths),
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(leftProfile, rightProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(
		result.Filesystem.ReadOnlyPaths, want.ReadOnlyPaths,
	) {
		t.Errorf(
			"ReadOnlyPaths = %v, want %v",
			result.Filesystem.ReadOnlyPaths, want.ReadOnlyPaths,
		)
	}

	if !slices.Equal(
		result.Filesystem.WriteOnlyPaths, want.WriteOnlyPaths,
	) {
		t.Errorf(
			"WriteOnlyPaths = %v, want %v",
			result.Filesystem.WriteOnlyPaths, want.WriteOnlyPaths,
		)
	}

	if !slices.Equal(
		result.Filesystem.ReadWritePaths, want.ReadWritePaths,
	) {
		t.Errorf(
			"ReadWritePaths = %v, want %v",
			result.Filesystem.ReadWritePaths, want.ReadWritePaths,
		)
	}
}
