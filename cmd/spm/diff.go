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
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
	"github.com/saschagrunert/security-profiles-merger/landlock"
	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

const (
	exitDiff         = 1
	diffProfileCount = 2

	diffUsage = `Usage: spm diff [options] <file1> <file2>

Compare two security profiles and show their differences.
Exit code 0 means equal, 1 means different, 2 means usage error.

Options:
`
)

var errDiffRequiresTwo = errors.New("diff requires exactly 2 profiles")

func runDiff(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, diffUsage)

		flags.PrintDefaults()
	}

	profileType := flags.String("type", "", "profile type: seccomp, apparmor, landlock (required)")
	format := flags.String("format", formatJSON, "output format: json, human")

	err := flags.Parse(args)
	if err != nil {
		return exitUsage
	}

	if *profileType == "" {
		_, _ = fmt.Fprintln(stderr, "error: --type is required")

		flags.PrintDefaults()

		return exitUsage
	}

	if *format != formatJSON && *format != formatHuman {
		_, _ = fmt.Fprintf(stderr, "error: unknown format %q (use json or human)\n", *format)

		return exitUsage
	}

	data, err := readDiffInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	return dispatchDiff(data, *profileType, *format, stdout, stderr)
}

func readDiffInputs(
	paths []string, stdin io.Reader,
) ([][]byte, error) {
	if len(paths) == 0 {
		data, err := readFromStdin(stdin)
		if err != nil {
			return nil, err
		}

		if len(data) != diffProfileCount {
			return nil, fmt.Errorf(
				"got %d from stdin: %w", len(data), errDiffRequiresTwo,
			)
		}

		return data, nil
	}

	if len(paths) != diffProfileCount {
		return nil, fmt.Errorf(
			"got %d files: %w", len(paths), errDiffRequiresTwo,
		)
	}

	return readInputs(paths, stdin)
}

type equalChecker interface {
	IsEqual() bool
}

func dispatchDiff(
	data [][]byte, profileType, format string, stdout, stderr io.Writer,
) int {
	switch profileType {
	case typeSeccomp:
		return diffProfiles(data, format, seccomp.Diff, seccomp.FormatDiff, stdout, stderr)
	case typeAppArmor:
		return diffProfiles(data, format, apparmor.Diff, apparmor.FormatDiff, stdout, stderr)
	case typeLandlock:
		return diffProfiles(data, format, landlock.Diff, landlock.FormatDiff, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(
			stderr,
			"error: unknown type %q (use seccomp, apparmor, or landlock)\n",
			profileType,
		)

		return exitUsage
	}
}

func diffProfiles[T any, D equalChecker](
	data [][]byte,
	format string,
	diffFn func(*T, *T) (*D, error),
	formatFn func(*D) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	result, err := diffFn(profiles[0], profiles[1])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	code := writeOutput(result, formatFn(result), format, stdout, stderr)
	if code != 0 {
		return exitUsage
	}

	if !(*result).IsEqual() {
		return exitDiff
	}

	return 0
}
