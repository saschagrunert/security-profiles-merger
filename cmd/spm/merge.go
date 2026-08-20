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
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
	"github.com/saschagrunert/security-profiles-merger/landlock"
	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

const mergeUsage = `Usage: spm merge [options] [files...]

Merge two or more security profiles using the given strategy.
Reads from stdin (as a JSON array) when no files are provided.

Options:
`

func runMerge(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(cmdMerge, flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, mergeUsage)

		flags.PrintDefaults()
	}

	profileType := flags.String("type", "", "profile type: seccomp, apparmor, landlock (required)")
	strategy := flags.String("strategy", "", "merge strategy: intersect, union (required)")
	format := flags.String("format", formatJSON, "output format: json, human")

	err := flags.Parse(args)
	if err != nil {
		return exitUsage
	}

	if *profileType == "" || *strategy == "" {
		_, _ = fmt.Fprintln(stderr, "error: --type and --strategy are required")

		flags.PrintDefaults()

		return exitUsage
	}

	if *strategy != strategyIntersect && *strategy != strategyUnion {
		_, _ = fmt.Fprintf(
			stderr, "error: unknown strategy %q (use intersect or union)\n", *strategy,
		)

		return exitUsage
	}

	if *format != formatJSON && *format != formatHuman {
		_, _ = fmt.Fprintf(stderr, "error: unknown format %q (use json or human)\n", *format)

		return exitUsage
	}

	data, err := readInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	return dispatchMerge(data, *profileType, *strategy, *format, stdout, stderr)
}

func dispatchMerge(
	data [][]byte, profileType, strategy, format string, stdout, stderr io.Writer,
) int {
	switch profileType {
	case typeSeccomp:
		return mergeProfiles(
			data, strategy, format,
			seccomp.Intersect, seccomp.Union, seccomp.FormatProfile,
			stdout, stderr,
		)
	case typeAppArmor:
		return mergeProfiles(
			data, strategy, format,
			apparmor.Intersect, apparmor.Union, apparmor.FormatProfile,
			stdout, stderr,
		)
	case typeLandlock:
		return mergeProfiles(
			data, strategy, format,
			landlock.Intersect, landlock.Union, landlock.FormatProfile,
			stdout, stderr,
		)
	default:
		_, _ = fmt.Fprintf(
			stderr, "error: unknown type %q (use seccomp, apparmor, or landlock)\n", profileType,
		)

		return exitUsage
	}
}

func mergeProfiles[T any](
	data [][]byte,
	strategy, format string,
	intersect, union func(...*T) (*T, error),
	formatFn func(*T) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	var mergeFn func(...*T) (*T, error)

	switch strategy {
	case strategyIntersect:
		mergeFn = intersect
	case strategyUnion:
		mergeFn = union
	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown strategy %q\n", strategy)

		return 1
	}

	result, err := mergeFn(profiles...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	return writeOutput(result, formatFn(result), format, stdout, stderr)
}

func readInputs(paths []string, stdin io.Reader) ([][]byte, error) {
	if len(paths) == 0 {
		return readFromStdin(stdin)
	}

	var result [][]byte

	for _, path := range paths {
		if path == "-" {
			items, err := readFromStdin(stdin)
			if err != nil {
				return nil, err
			}

			result = append(result, items...)

			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		if info.Size() > maxInputSize {
			return nil, fmt.Errorf(
				"reading %s: %w (%d bytes)", path, errFileTooLarge, info.Size(),
			)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		result = append(result, data)
	}

	return result, nil
}

const maxInputSize = 10 << 20

var (
	errEmptyInput    = errors.New("no input provided")
	errStdinTooLarge = fmt.Errorf("stdin input exceeds %d bytes", maxInputSize)
	errFileTooLarge  = fmt.Errorf("file exceeds %d byte limit", maxInputSize)
)

func readFromStdin(reader io.Reader) ([][]byte, error) {
	if reader == nil {
		return nil, errEmptyInput
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}

	if len(data) > maxInputSize {
		return nil, errStdinTooLarge
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmptyInput
	}

	var array []json.RawMessage

	err = json.Unmarshal(data, &array)
	if err == nil {
		if len(array) == 0 {
			return nil, errEmptyInput
		}

		result := make([][]byte, len(array))
		for idx, item := range array {
			result[idx] = item
		}

		return result, nil
	}

	return [][]byte{data}, nil
}

func unmarshalAll[T any](data [][]byte) ([]*T, error) {
	profiles := make([]*T, len(data))

	for idx, raw := range data {
		var profile T

		err := json.Unmarshal(raw, &profile)
		if err != nil {
			return nil, fmt.Errorf("parsing profile %d: %w", idx, err)
		}

		profiles[idx] = &profile
	}

	return profiles, nil
}

func writeOutput(
	result any, humanStr, format string, stdout, stderr io.Writer,
) int {
	switch format {
	case formatHuman:
		_, _ = fmt.Fprintln(stdout, humanStr)
	default:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")

		err := enc.Encode(result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: encoding output: %v\n", err)

			return 1
		}
	}

	return 0
}
