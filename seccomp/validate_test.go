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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := seccomp.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	err := seccomp.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownDefaultAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: "SCMP_ACT_INVALID",
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown default action")
	}
}

func TestValidateUnknownSyscallAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: "SCMP_ACT_BOGUS"},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown syscall action")
	}
}

func TestValidateAllKnownActions(t *testing.T) {
	t.Parallel()

	actions := []specs.LinuxSeccompAction{
		specs.ActKillProcess,
		specs.ActKillThread,
		specs.ActKill,
		specs.ActTrap,
		specs.ActErrno,
		specs.ActTrace,
		specs.ActNotify,
		specs.ActLog,
		specs.ActAllow,
	}

	for _, action := range actions {
		profile := &specs.LinuxSeccomp{DefaultAction: action}

		err := seccomp.Validate(profile)
		if err != nil {
			t.Errorf("unexpected error for action %q: %v", action, err)
		}
	}
}
