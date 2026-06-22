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

package seccomp_test

import (
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

func ExampleIntersect() {
	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(baseline, profile)
	if err != nil {
		panic(err)
	}

	fmt.Println("Default:", result.DefaultAction)

	for _, sc := range result.Syscalls {
		fmt.Println("Syscall:", sc.Names[0], "->", sc.Action)
	}

	// Output:
	// Default: SCMP_ACT_ERRNO
	// Syscall: read -> SCMP_ACT_ALLOW
}

func ExampleUnion() {
	recording1 := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	recording2 := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(recording1, recording2)
	if err != nil {
		panic(err)
	}

	fmt.Println("Default:", result.DefaultAction)

	for _, sc := range result.Syscalls {
		fmt.Println("Syscall:", sc.Names[0], "->", sc.Action)
	}

	// Output:
	// Default: SCMP_ACT_ERRNO
	// Syscall: read -> SCMP_ACT_ALLOW
	// Syscall: write -> SCMP_ACT_ALLOW
}
