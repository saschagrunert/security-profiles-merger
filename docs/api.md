# API Reference

<!-- toc -->
- [seccomp](#seccomp)
  - [Functions](#functions)
  - [Types](#types)
  - [Errors](#errors)
  - [Merge semantics](#merge-semantics)
- [apparmor](#apparmor)
  - [Functions](#functions-1)
  - [Errors](#errors-1)
  - [Types](#types-1)
  - [Nil vs empty semantics](#nil-vs-empty-semantics)
  - [Filesystem merge](#filesystem-merge)
- [landlock](#landlock)
  - [Functions](#functions-2)
  - [Errors](#errors-2)
  - [Types](#types-2)
  - [Handled access semantics](#handled-access-semantics)
  - [IPC scoping](#ipc-scoping)
  - [Path and network rules](#path-and-network-rules)
<!-- /toc -->

For full Go documentation, see the
[pkg.go.dev reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger).

## seccomp

Seccomp profile merge operating on `specs.LinuxSeccomp` from the
[OCI runtime-spec](https://github.com/opencontainers/runtime-spec).

```go
import "github.com/saschagrunert/security-profiles-merger/seccomp"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge profiles via intersection (most restrictive wins) |
| `Union` | Merge profiles via union (least restrictive wins) |
| `IntersectSyscalls` | Intersect two bare syscall slices without a DefaultAction |
| `UnionSyscalls` | Union two bare syscall slices without a DefaultAction |
| `MoreRestrictive` | Return the more restrictive of two seccomp actions |
| `LessRestrictive` | Return the less restrictive of two seccomp actions |
| `Validate` | Check for known actions and non-empty syscall names |
| `ValidateStrict` | All Validate checks plus duplicates, unknown archs/flags/operators |
| `FormatProfile` | Human-readable representation of a seccomp profile |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/seccomp)
for full signatures and documentation.

### Types

Diff types (`ProfileDiff`, `ActionDiff`, `UintPtrDiff`, `StringDiff`,
`SliceDiff`, `SyscallsDiff`, `SyscallEntry`, `SyscallChange`, `SyscallDetail`)
are documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/seccomp#ProfileDiff).

`SyscallEntry` and `SyscallDetail` implement `fmt.Stringer` for human-readable
formatting.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrUnknownAction`,
`ErrEmptySyscallNames`, `ErrDuplicateSyscallName`, `ErrUnknownOperator`,
`ErrArgIndexOutOfRange`, `ErrUnknownArch`, `ErrUnknownFlag`, etc.) are documented
in the [package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/seccomp#pkg-variables).

### Merge semantics

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

## apparmor

AppArmor profile merge using structured profile types defined in this package.

```go
import "github.com/saschagrunert/security-profiles-merger/apparmor"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection; capabilities/paths intersected, network AND |
| `Union` | Merge via union; all rules combined, network OR |
| `Validate` | Check for cross-category path conflicts and known capabilities |
| `ValidateStrict` | All Validate checks plus duplicate executables/libraries |
| `FormatProfile` | Human-readable representation of an AppArmor profile |
| `IsGlobPattern` | Report whether a path contains AppArmor glob tokens |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/apparmor)
for full signatures and documentation.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrDuplicatePath`,
`ErrUnknownCapability`, `ErrDuplicateExecutablePath`, etc.) are documented
in the [package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/apparmor#pkg-variables).

### Types

Core types (`Profile`, `CapabilityRules`, `ExecutableRules`, `FilesystemRules`,
`NetworkRules`, `AllowedProtocols`) and diff types (`ProfileDiff`,
`StringSliceDiff`, `FilesystemDiff`, `NetworkDiff`, `BoolPtrDiff`) are
documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/apparmor#Profile).

`Profile`, `ExecutableRules`, `FilesystemRules`, `NetworkRules`, and
`CapabilityRules` implement `fmt.Stringer` for human-readable formatting.

### Nil vs empty semantics

A nil field means "unspecified" and defers to the other profile during merge. A
non-nil field with empty contents means "explicitly no permissions". For example,
intersecting `{caps: [NET_ADMIN]}` with `{caps: nil}` yields `[NET_ADMIN]`,
while intersecting with `{caps: []}` yields `[]`.

### Filesystem merge

Paths are expanded into read/write permission pairs, merged per path (AND for
intersection, OR for union), and collapsed back into read-only, write-only, and
read-write lists. A read-write path intersected with a read-only path becomes
read-only (only the shared permission survives). A read-only path in one profile
and write-only in the other is dropped on intersection (no shared permissions)
but becomes read-write on union. When two non-nil filesystem rule sets produce
no overlapping paths after intersection, the result is a non-nil empty
`FilesystemRules` (preserving the nil-vs-empty distinction).

## landlock

Landlock profile merge for Linux unprivileged sandboxing rulesets.

```go
import "github.com/saschagrunert/security-profiles-merger/landlock"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection; handled sets unioned, rules intersected |
| `Union` | Merge via union; handled sets intersected, rules unioned |
| `Validate` | Check for known rights, empty paths, and duplicate rules |
| `ValidateStrict` | All Validate checks plus unhandled-right detection |
| `FormatProfile` | Human-readable representation of a Landlock profile |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/landlock)
for full signatures and documentation.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrUnknownRight`,
`ErrDuplicateRule`, `ErrEmptyPath`, `ErrUnhandledRight`, `ErrDuplicateRight`,
etc.) are documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/landlock#pkg-variables).

### Types

Core types (`Profile`, `FSAccessRight`, `NetAccessRight`, `ScopeRight`,
`PathRule`, `NetRule`) and diff types (`ProfileDiff`, `RightsDiff`,
`PathRulesDiff`, `PathRuleChange`, `NetRulesDiff`, `NetRuleChange`) are
documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/landlock#Profile).

`Profile`, `PathRule`, and `NetRule` implement `fmt.Stringer` for human-readable
formatting.

### Handled access semantics

Landlock has inverted merge semantics for handled-access sets and scope
restrictions compared to rules. Unhandled access rights are implicitly allowed,
so intersection unions the handled sets and scoped sets (handling more rights /
scoping more makes the ruleset more restrictive), and union intersects them
(handling fewer rights / scoping less makes it less restrictive).

### IPC scoping

Scope restrictions (abstract_unix_socket, signal) have no exceptions via rules.
Once scoped, access outside the Landlock domain is fully blocked. During merge,
scoped sets follow the same inverted semantics as handled access sets.

### Path and network rules

During intersection, rules for entries present in both profiles have their
access rights intersected. Entries only in one profile are dropped if the access
right is handled by the other profile, or kept if unhandled. During union,
access rights are combined for matching entries, and all non-matching entries are
kept.
