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

func TestFormatProfile(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_X86_64 " +
		"read->SCMP_ACT_ALLOW write->SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileNil(t *testing.T) {
	t.Parallel()

	const want = "Profile{<nil>}"

	if got := seccomp.FormatProfile(nil); got != want {
		t.Errorf("FormatProfile(nil) = %q, want %q", got, want)
	}
}

func TestFormatProfileEmpty(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
	}

	const want = "Profile{default:SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithArgs(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"clone"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO clone([0]SCMP_CMP_MASKED_EQ:65536:0)->SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithValueTwo(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"clone"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 0x10000, ValueTwo: 0xFF, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO clone([0]SCMP_CMP_MASKED_EQ:65536:255)->SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileMultipleArchitectures(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchARM},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_X86_64,SCMP_ARCH_ARM}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithDefaultErrnoRet(t *testing.T) {
	t.Parallel()

	errnoRet := uint(38)
	profile := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errnoRet,
	}

	const want = "Profile{default:SCMP_ACT_ERRNO defaultErrno:38}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithFlags(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_LOG"},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO flags:SECCOMP_FILTER_FLAG_LOG}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithListener(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/seccomp-agent.sock",
		ListenerMetadata: "container-id=abc",
	}

	const want = "Profile{default:SCMP_ACT_ERRNO " +
		"listener:/run/seccomp-agent.sock listenerMeta:container-id=abc}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithSyscallErrnoRet(t *testing.T) {
	t.Parallel()

	errnoRet := uint(1)
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:    []string{"mount"},
				Action:   specs.ActErrno,
				ErrnoRet: &errnoRet,
			},
		},
	}

	const want = "Profile{default:SCMP_ACT_ALLOW mount->SCMP_ACT_ERRNO(errno:1)}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileListenerMetadataWithoutPath(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerMetadata: "should-be-suppressed",
	}

	const want = "Profile{default:SCMP_ACT_ERRNO}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}
