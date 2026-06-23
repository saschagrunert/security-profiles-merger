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

package landlock_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/landlock"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := landlock.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
			},
		}},
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownHandledFS(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus_right"},
		HandledAccessNet: nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown HandledAccessFS")
	}
}

func TestValidateUnknownHandledNet(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: []landlock.NetAccessRight{"bogus_net"},
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown HandledAccessNet")
	}
}

func TestValidateUnknownPathRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{"read_bogus"},
		}},
		NetRules: nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown path rule right")
	}
}

func TestValidateUnknownNetRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{"bind_udp"},
		}},
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown net rule right")
	}
}

func TestValidateEmpty(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error for empty profile: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus_fs"},
		HandledAccessNet: []landlock.NetAccessRight{"bogus_net"},
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{"read_bogus"},
		}},
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{"bind_bogus"},
		}},
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for multiple invalid rights")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}

	msg := err.Error()

	for _, want := range []string{
		"HandledAccessFS", "HandledAccessNet",
		"PathRules[0]", "NetRules[0]",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

func TestValidateAllKnownFSRights(t *testing.T) {
	t.Parallel()

	all := []landlock.FSAccessRight{
		landlock.FSAccessExecute,
		landlock.FSAccessWriteFile,
		landlock.FSAccessReadFile,
		landlock.FSAccessReadDir,
		landlock.FSAccessRemoveDir,
		landlock.FSAccessRemoveFile,
		landlock.FSAccessMakeChar,
		landlock.FSAccessMakeDir,
		landlock.FSAccessMakeReg,
		landlock.FSAccessMakeSock,
		landlock.FSAccessMakeFIFO,
		landlock.FSAccessMakeSym,
		landlock.FSAccessMakeBlock,
		landlock.FSAccessRefer,
		landlock.FSAccessTruncate,
		landlock.FSAccessIOCTLDev,
	}

	profile := &landlock.Profile{
		HandledAccessFS:  all,
		HandledAccessNet: nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
