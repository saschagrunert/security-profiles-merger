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
	"encoding/json"
	"flag"
	"fmt"
	"io"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
	"github.com/saschagrunert/security-profiles-merger/landlock"
	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

const validateUsage = `Usage: spm validate [options] [files...]

Validate one or more security profiles.
Reads from stdin (as a JSON array) when no files are provided.

Options:
`

func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(cmdValidate, flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, validateUsage)

		flags.PrintDefaults()
	}

	profileType := flags.String("type", "", "profile type: seccomp, apparmor, landlock (required)")
	strict := flags.Bool("strict", false, "use strict validation")
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

	data, err := readInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	switch *profileType {
	case typeSeccomp:
		return validateSeccomp(data, *strict, *format, stdout, stderr)
	case typeAppArmor:
		return validateAppArmor(data, *strict, *format, stdout, stderr)
	case typeLandlock:
		return validateLandlock(data, *strict, *format, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(
			stderr,
			"error: unknown type %q (use seccomp, apparmor, or landlock)\n",
			*profileType,
		)

		return exitUsage
	}
}

func validateSeccomp(
	data [][]byte, strict bool, format string, stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[specs.LinuxSeccomp](data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	validate := seccomp.Validate
	if strict {
		validate = seccomp.ValidateStrict
	}

	for idx, profile := range profiles {
		err := validate(profile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "profile %d: %v\n", idx, err)

			return 1
		}
	}

	return writeValidated(profiles, seccompFormatAll(profiles), format, stdout, stderr)
}

func validateAppArmor(
	data [][]byte, strict bool, format string, stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[apparmor.Profile](data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	validate := apparmor.Validate
	if strict {
		validate = apparmor.ValidateStrict
	}

	for idx, profile := range profiles {
		err := validate(profile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "profile %d: %v\n", idx, err)

			return 1
		}
	}

	return writeValidated(profiles, apparmorFormatAll(profiles), format, stdout, stderr)
}

func validateLandlock(
	data [][]byte, strict bool, format string, stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[landlock.Profile](data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	validate := landlock.Validate
	if strict {
		validate = landlock.ValidateStrict
	}

	for idx, profile := range profiles {
		err := validate(profile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "profile %d: %v\n", idx, err)

			return 1
		}
	}

	return writeValidated(profiles, landlockFormatAll(profiles), format, stdout, stderr)
}

func writeValidated[T any](
	profiles []*T, humanStrs []string, format string, stdout, stderr io.Writer,
) int {
	if len(profiles) == 1 {
		return writeOutput(profiles[0], humanStrs[0], format, stdout, stderr)
	}

	switch format {
	case formatHuman:
		for _, str := range humanStrs {
			_, _ = fmt.Fprintln(stdout, str)
		}
	default:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")

		err := enc.Encode(profiles)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: encoding output: %v\n", err)

			return 1
		}
	}

	return 0
}

func seccompFormatAll(profiles []*specs.LinuxSeccomp) []string {
	result := make([]string, len(profiles))
	for idx, p := range profiles {
		result[idx] = seccomp.FormatProfile(p)
	}

	return result
}

func apparmorFormatAll(profiles []*apparmor.Profile) []string {
	result := make([]string, len(profiles))
	for idx, p := range profiles {
		result[idx] = apparmor.FormatProfile(p)
	}

	return result
}

func landlockFormatAll(profiles []*landlock.Profile) []string {
	result := make([]string, len(profiles))
	for idx, p := range profiles {
		result[idx] = landlock.FormatProfile(p)
	}

	return result
}
