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

// Package main implements the spm CLI for merging and validating security profiles.
package main

import (
	"fmt"
	"io"
	"os"
)

const (
	exitUsage = 2

	cmdMerge    = "merge"
	cmdValidate = "validate"

	typeSeccomp  = "seccomp"
	typeAppArmor = "apparmor"
	typeLandlock = "landlock"

	strategyIntersect = "intersect"
	strategyUnion     = "union"

	formatJSON  = "json"
	formatHuman = "human"
)

const usage = `Usage: spm <command> [options] [files...]

Commands:
  merge      Merge two or more security profiles
  validate   Validate one or more security profiles

Run 'spm <command> --help' for details on each command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)

		return exitUsage
	}

	switch args[0] {
	case cmdMerge:
		return runMerge(args[1:], stdin, stdout, stderr)
	case cmdValidate:
		return runValidate(args[1:], stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[0], usage)

		return exitUsage
	}
}
