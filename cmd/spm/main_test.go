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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFromStdinNilReader(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(nil)
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinEmpty(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader(""))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinWhitespace(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader("   \n\t  "))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinEmptyArray(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader("[]"))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinJSONArray(t *testing.T) {
	t.Parallel()

	result, err := readFromStdin(strings.NewReader(`[{"a":1},{"b":2}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("got %d items, want 2", len(result))
	}
}

func TestReadFromStdinSingleObject(t *testing.T) {
	t.Parallel()

	result, err := readFromStdin(strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("got %d items, want 1", len(result))
	}
}

func TestReadInputsFromFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file1 := filepath.Join(dir, "a.json")
	file2 := filepath.Join(dir, "b.json")

	err := os.WriteFile(file1, []byte(`{"a":1}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(file2, []byte(`{"b":2}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	result, err := readInputs([]string{file1, file2}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("got %d items, want 2", len(result))
	}
}

func TestReadInputsNonexistentFile(t *testing.T) {
	t.Parallel()

	_, err := readInputs([]string{"/no/such/file.json"}, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestReadInputsFileTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	large := filepath.Join(dir, "large.json")

	err := os.WriteFile(large, make([]byte, maxInputSize+1), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readInputs([]string{large}, nil)
	if !errors.Is(err, errFileTooLarge) {
		t.Errorf("error = %v, want %v", err, errFileTooLarge)
	}
}

func TestReadInputsStdinDash(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`{"a":1}`)

	result, err := readInputs([]string{"-"}, stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("got %d items, want 1", len(result))
	}
}

func TestReadInputsNoPathsUsesStdin(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`[{"a":1},{"b":2}]`)

	result, err := readInputs(nil, stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("got %d items, want 2", len(result))
	}
}

func TestErrorSentinels(t *testing.T) {
	t.Parallel()

	t.Run("errEmptyInput", func(t *testing.T) {
		t.Parallel()

		if errEmptyInput == nil {
			t.Fatal("errEmptyInput should not be nil")
		}
	})

	t.Run("errStdinTooLarge", func(t *testing.T) {
		t.Parallel()

		if errStdinTooLarge == nil {
			t.Fatal("errStdinTooLarge should not be nil")
		}
	})

	t.Run("errFileTooLarge", func(t *testing.T) {
		t.Parallel()

		if errFileTooLarge == nil {
			t.Fatal("errFileTooLarge should not be nil")
		}
	})
}
