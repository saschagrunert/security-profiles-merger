# security-profiles-merger

[![ci](https://github.com/saschagrunert/security-profiles-merger/actions/workflows/ci.yml/badge.svg)](https://github.com/saschagrunert/security-profiles-merger/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/saschagrunert/security-profiles-merger/graph/badge.svg)](https://codecov.io/gh/saschagrunert/security-profiles-merger)
[![Go Report Card](https://goreportcard.com/badge/github.com/saschagrunert/security-profiles-merger)](https://goreportcard.com/report/github.com/saschagrunert/security-profiles-merger)
[![Go Reference](https://pkg.go.dev/badge/github.com/saschagrunert/security-profiles-merger.svg)](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger)

A standalone Go library for merging security profiles (seccomp, AppArmor) used
by Kubernetes CRI runtimes and the Security Profiles Operator.

## Overview

This library provides two core operations on security profiles:

- **Intersect**: Produces an effective profile that permits an operation only if
  all input profiles permit it. Used by CRI runtimes (CRI-O, containerd) to
  merge OCI-pulled profiles with node baselines per
  [KEP-6061](https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/6061-oci-artifact-security-profiles).
- **Union**: Produces a profile that permits an operation if any input profile
  permits it. Used by the
  [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
  to merge recorded profiles.

## Installation

```
go get github.com/saschagrunert/security-profiles-merger
```

## Packages

### seccomp

Seccomp profile merge operating on `specs.LinuxSeccomp` from the
[OCI runtime-spec](https://github.com/opencontainers/runtime-spec).

```go
import "github.com/saschagrunert/security-profiles-merger/seccomp"
```

**Functions:**

- `seccomp.Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)` -
  Merge profiles via intersection. The resulting profile permits a syscall only
  if all input profiles permit it. For each syscall present in multiple profiles,
  the more restrictive action is chosen.
- `seccomp.Union(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)` -
  Merge profiles via union. The resulting profile permits a syscall if any input
  profile permits it. For each overlapping syscall, the less restrictive action
  is chosen.
- `seccomp.MoreRestrictive(a, b LinuxSeccompAction) LinuxSeccompAction` -
  Returns the more restrictive of two seccomp actions.
- `seccomp.LessRestrictive(a, b LinuxSeccompAction) LinuxSeccompAction` -
  Returns the less restrictive of two seccomp actions.

**Merge semantics:**

- Default actions are merged using the same restrictiveness comparison as
  syscalls.
- Architectures: intersection keeps only architectures present in all profiles;
  union combines all. An empty architecture list means "all architectures".
- Flags: intersection keeps only flags present in all profiles; union combines
  all. An empty flag list means "no flags".
- Argument filters: during intersection, non-identical argument filters result
  in a conservative denial (`SCMP_ACT_KILL_PROCESS`). During union, argument
  filters from both sides are combined. When only one side has argument filters,
  intersection keeps them and union drops them.
- `DefaultErrnoRet` is taken from whichever profile's default action is selected.
- `ListenerPath` and `ListenerMetadata` are taken from the first profile.

**Action restrictiveness ordering** (most to least restrictive):

`KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > TRACE > NOTIFY > LOG > ALLOW`

Unknown actions are treated as maximally restrictive.

### apparmor

AppArmor profile merge using structured profile types defined in this package.

```go
import "github.com/saschagrunert/security-profiles-merger/apparmor"
```

**Functions:**

- `apparmor.Intersect(profiles ...*Profile) (*Profile, error)` -
  Merge profiles via intersection. Capabilities, executables, libraries, and
  filesystem paths are intersected; boolean network permissions use AND semantics.
- `apparmor.Union(profiles ...*Profile) (*Profile, error)` -
  Merge profiles via union. All rule types are combined; boolean network
  permissions use OR semantics.

**Types:**

- `Profile` - Top-level profile containing all rule sections.
- `CapabilityRules` - Allowed Linux capabilities.
- `ExecutableRules` - Allowed executables and libraries.
- `FilesystemRules` - Read-only, write-only, and read-write path rules.
- `NetworkRules` - Raw socket access and protocol permissions.
- `AllowedProtocols` - TCP/UDP protocol permissions.

**Nil vs empty semantics:** A nil field means "unspecified" and defers to the
other profile during merge. A non-nil field with empty contents means "explicitly
no permissions". For example, intersecting `{caps: [NET_ADMIN]}` with
`{caps: nil}` yields `[NET_ADMIN]`, while intersecting with `{caps: []}` yields
`[]`.

**Filesystem merge:** Paths are expanded into read/write permission pairs, merged
per path (AND for intersection, OR for union), and collapsed back into
read-only, write-only, and read-write lists. A read-write path intersected with
a read-only path becomes read-only (only the shared permission survives). A
read-only path in one profile and write-only in the other is dropped on
intersection (no shared permissions) but becomes read-write on union.

## Usage

### CRI runtime: merge OCI-pulled profile with node baseline (intersection)

```go
effective, err := seccomp.Intersect(nodeBaseline, ociPulledProfile)
if err != nil {
    return err
}
// effective permits only syscalls allowed by both profiles
```

### SPO: combine recorded profiles (union)

```go
combined, err := seccomp.Union(recording1, recording2, recording3)
if err != nil {
    return err
}
// combined permits all syscalls seen in any recording
```

### AppArmor profile merge

```go
aaEffective, err := apparmor.Intersect(baseProfile, ociProfile)
aaCombined, err := apparmor.Union(recorded1, recorded2)
```

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the
[community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at the
[SIG Node mailing list](https://groups.google.com/forum/#!forum/kubernetes-sig-node).

### Code of Conduct

Participation in the Kubernetes community is governed by the
[Kubernetes Code of Conduct](code-of-conduct.md).
