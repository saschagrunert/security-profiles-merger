# Kubernetes Security Profiles Merger

[![ci](https://github.com/saschagrunert/security-profiles-merger/actions/workflows/ci.yml/badge.svg)](https://github.com/saschagrunert/security-profiles-merger/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/saschagrunert/security-profiles-merger/graph/badge.svg)](https://codecov.io/gh/saschagrunert/security-profiles-merger)
[![Go Reference](https://pkg.go.dev/badge/github.com/saschagrunert/security-profiles-merger.svg)](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger)

A standalone Go library for merging security profiles
([seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html),
[AppArmor](https://apparmor.net/),
[Landlock](https://landlock.io/)) used by [Kubernetes](https://kubernetes.io) CRI runtimes and the
[Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator).

## Overview

This library provides two core operations on security profiles:

- **Intersect**: Produces an effective profile that permits an operation only if
  all input profiles permit it. Used by CRI runtimes (CRI-O, containerd) to
  merge OCI-pulled profiles with node baselines per
  [KEP-6061](https://github.com/kubernetes/enhancements/issues/6061).
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
- `seccomp.UnionSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall` -
  Merge two bare syscall slices via union without a profile-level DefaultAction.
  Unlike `Union`, no entries are elided and unmatched entries keep their original
  action. Multi-name entries are normalized to one-name-per-entry.
- `seccomp.IntersectSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall` -
  Merge two bare syscall slices via intersection without a profile-level
  DefaultAction. Syscalls present in only one list are dropped. Multi-name
  entries are normalized to one-name-per-entry and the result is sorted by name.
- `seccomp.MoreRestrictive(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction` -
  Returns the more restrictive of two seccomp actions.
- `seccomp.LessRestrictive(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction` -
  Returns the less restrictive of two seccomp actions.
- `seccomp.Validate(profile *specs.LinuxSeccomp) error` -
  Checks that a profile contains only known actions and that every syscall entry
  has at least one name.
- `seccomp.ValidateStrict(profile *specs.LinuxSeccomp) error` -
  Performs all checks from Validate and additionally detects duplicate syscall
  names across entries. Use Validate for merge inputs and ValidateStrict for
  user-authored profiles.
- `seccomp.FormatProfile(profile *specs.LinuxSeccomp) string` -
  Returns a human-readable representation of a seccomp profile.

**Errors:**

- `seccomp.ErrNoProfiles` - returned when no profiles are provided.
- `seccomp.ErrNilProfile` - returned when a nil profile is provided.
- `seccomp.ErrUnknownAction` - returned when a profile contains an unrecognized action.
- `seccomp.ErrEmptySyscallNames` - returned when a syscall entry has no names.
- `seccomp.ErrDuplicateSyscallName` - returned by ValidateStrict when the same
  syscall name appears in multiple entries.

**Merge semantics:**

- Default actions are merged using the same restrictiveness comparison as
  syscalls.
- Architectures: intersection keeps only architectures present in all profiles;
  union combines all. An empty architecture list is treated as "unspecified" and
  defers to the other profile. Per the OCI runtime-spec, empty means "native
  architecture only", but the native architecture is unknown at merge time.
  Callers that need precise architecture intersection should populate the native
  architecture explicitly before merging.
- Flags: intersection keeps only flags present in all profiles; union combines
  all. An empty flag list is treated as "unspecified" and defers to the other
  profile during intersection, matching the architecture behavior.
- Argument filters: during intersection, non-identical argument filters result
  in a conservative denial (`SCMP_ACT_KILL_PROCESS`). During union, argument
  filters from both sides are combined. When only one side has argument filters,
  intersection keeps them and union drops them.
- `DefaultErrnoRet` is taken from whichever profile's default action is selected.
  When both profiles share the same action, the earlier (leftmost) profile's
  `DefaultErrnoRet` wins. The same applies to per-syscall `ErrnoRet`.
- `ListenerPath` and `ListenerMetadata` are taken from the first profile.

**Action restrictiveness ordering** (most to least restrictive):

`KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > NOTIFY > TRACE > LOG > ALLOW`

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
- `apparmor.Validate(profile *Profile) error` -
  Checks that no path appears in multiple filesystem categories (e.g. both
  read-only and write-only).
- `apparmor.ValidateStrict(profile *Profile) error` -
  Performs all checks from Validate and additionally verifies that no path
  appears more than once in AllowedExecutables or AllowedLibraries. Use
  Validate for merge inputs and ValidateStrict for user-authored profiles.
- `apparmor.FormatProfile(profile *Profile) string` -
  Returns a human-readable representation of an AppArmor profile.

**Errors:**

- `apparmor.ErrNoProfiles` - returned when no profiles are provided.
- `apparmor.ErrNilProfile` - returned when a nil profile is provided.
- `apparmor.ErrDuplicatePath` - returned when a path appears in multiple
  filesystem categories.
- `apparmor.ErrDuplicatePathInCategory` - returned when a path appears more
  than once within the same filesystem category.
- `apparmor.ErrDuplicateCapability` - returned when the same capability appears
  more than once in AllowedCapabilities.
- `apparmor.ErrEmptyPath` - returned when a path rule contains an empty string.
- `apparmor.ErrEmptyCapability` - returned when a capability entry is an empty
  string.
- `apparmor.ErrDuplicateExecutablePath` - returned by ValidateStrict when the
  same path appears more than once in AllowedExecutables or AllowedLibraries.

**Types:**

- `Profile` - Top-level profile containing all rule sections.
- `CapabilityRules` - Allowed Linux capabilities.
- `ExecutableRules` - Allowed executables and libraries.
- `FilesystemRules` - Read-only, write-only, and read-write path rules.
- `NetworkRules` - Raw socket access and protocol permissions.
- `AllowedProtocols` - TCP/UDP protocol permissions.

`Profile`, `ExecutableRules`, `FilesystemRules`, `NetworkRules`, and
`CapabilityRules` implement `fmt.Stringer` for human-readable formatting.

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
intersection (no shared permissions) but becomes read-write on union. When two
non-nil filesystem rule sets produce no overlapping paths after intersection, the
result is a non-nil empty `FilesystemRules` (preserving the nil-vs-empty
distinction).

### landlock

Landlock profile merge for Linux unprivileged sandboxing rulesets.

```go
import "github.com/saschagrunert/security-profiles-merger/landlock"
```

**Functions:**

- `landlock.Intersect(profiles ...*Profile) (*Profile, error)` -
  Merge profiles via intersection. HandledAccessFS and HandledAccessNet are
  unioned (more handled rights = more restrictive). Path and network rules
  are intersected per key.
- `landlock.Union(profiles ...*Profile) (*Profile, error)` -
  Merge profiles via union. HandledAccessFS and HandledAccessNet are
  intersected (fewer handled rights = less restrictive). Path and network
  rules are unioned per key.
- `landlock.Validate(profile *Profile) error` -
  Checks that a profile contains only known access rights, has no empty paths,
  and has no duplicate path or port rules.
- `landlock.ValidateStrict(profile *Profile) error` -
  Performs all checks from Validate and additionally verifies that every rule's
  access rights are a subset of the corresponding handled access set. Use
  Validate for merge inputs and ValidateStrict for user-authored profiles.
- `landlock.FormatProfile(profile *Profile) string` -
  Returns a human-readable representation of a Landlock profile.

**Errors:**

- `landlock.ErrNoProfiles` - returned when no profiles are provided.
- `landlock.ErrNilProfile` - returned when a nil profile is provided.
- `landlock.ErrUnknownRight` - returned when a profile contains an unrecognized
  access right.
- `landlock.ErrDuplicateRule` - returned when a profile contains multiple rules
  for the same path or port.
- `landlock.ErrEmptyPath` - returned when a path rule has an empty path string.
- `landlock.ErrUnhandledRight` - returned by ValidateStrict when a rule grants
  an access right not listed in the handled access set.
- `landlock.ErrDuplicateRight` - returned when the same access right appears
  more than once in a handled set or rule.

**Types:**

- `Profile` - Top-level Landlock ruleset containing handled access sets and rules.
- `FSAccessRight` - Filesystem access right (execute, read_file, write_file, etc.).
- `NetAccessRight` - Network access right (bind_tcp, connect_tcp, bind_udp,
  connect_udp, sendto_udp).
- `PathRule` - Per-path filesystem access rights.
- `NetRule` - Per-port network access rights.

`Profile`, `PathRule`, and `NetRule` implement `fmt.Stringer` for human-readable
formatting.

**Handled access semantics:** Landlock has inverted merge semantics for
handled-access sets compared to rules. Unhandled access rights are implicitly
allowed, so intersection unions the handled sets (handling more rights makes
the ruleset more restrictive), and union intersects them (handling fewer rights
makes it less restrictive).

**Path and network rules:** During intersection, rules for entries present in
both profiles have their access rights intersected. Entries only in one profile
are dropped if the access right is handled by the other profile, or kept if
unhandled. During union, access rights are combined for matching entries, and
all non-matching entries are kept.

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

### Landlock profile merge

```go
llEffective, err := landlock.Intersect(baseRuleset, ociRuleset)
llCombined, err := landlock.Union(recorded1, recorded2)
```

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the
[community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at the
[SIG Node mailing list](https://groups.google.com/forum/#!forum/kubernetes-sig-node).

### Code of Conduct

Participation in the Kubernetes community is governed by the
[Kubernetes Code of Conduct](code-of-conduct.md).
