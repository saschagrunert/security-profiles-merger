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

package apparmor

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

var globTokenRe = regexp.MustCompile(`\*\*?|\?|\{[^}]+\}`)

// globToRegex converts an AppArmor glob pattern to a Go regular expression.
// Panics on compilation failure, which cannot occur because all literal
// segments are escaped and glob tokens map to fixed regex fragments.
var neverMatchRe = regexp.MustCompile(`^\x00$`)

func globToRegex(pattern string) *regexp.Regexp {
	if !utf8.ValidString(pattern) {
		return neverMatchRe
	}

	var builder strings.Builder

	builder.WriteString("^")

	lastEnd := 0

	for _, loc := range globTokenRe.FindAllStringIndex(pattern, -1) {
		builder.WriteString(regexp.QuoteMeta(pattern[lastEnd:loc[0]]))

		token := pattern[loc[0]:loc[1]]

		switch token {
		case "**":
			builder.WriteString(`[^\000]*`)
		case "*":
			builder.WriteString(`[^/\000]*`)
		case "?":
			builder.WriteString(`[^/\000]`)
		default:
			inner := token[1 : len(token)-1]
			alternatives := strings.Split(inner, ",")

			for idx := range alternatives {
				alternatives[idx] = regexp.QuoteMeta(alternatives[idx])
			}

			builder.WriteString("(")
			builder.WriteString(strings.Join(alternatives, "|"))
			builder.WriteString(")")
		}

		lastEnd = loc[1]
	}

	builder.WriteString(regexp.QuoteMeta(pattern[lastEnd:]))
	builder.WriteString("$")

	return regexp.MustCompile(builder.String())
}

type apparmorPath struct {
	pattern string
	expr    *regexp.Regexp
}

type pathSet struct {
	paths []apparmorPath
}

func newPathSet(patterns []string) pathSet {
	var set pathSet

	for _, pat := range patterns {
		set.add(pat)
	}

	return set
}

// findMatch returns the index of the first entry whose regex matches path,
// or whose pattern equals path exactly. Only checks forward matching
// (existing pattern covers incoming path).
func (set *pathSet) findMatch(path string) int {
	for idx, entry := range set.paths {
		if entry.pattern == path {
			return idx
		}

		if entry.expr.MatchString(path) {
			return idx
		}
	}

	return -1
}

func (set *pathSet) matches(path string) bool {
	return set.findMatch(path) >= 0
}

// popInteracting finds the first entry that interacts with path and removes it.
// It checks both directions: existing patterns matching the incoming path
// (forward), and the incoming path matching existing non-glob entries
// (reverse). Returns the broader of the two patterns for promotion.
func (set *pathSet) popInteracting(path string) *string {
	for idx, entry := range set.paths {
		if entry.pattern == path {
			ret := entry.pattern
			set.paths[idx] = set.paths[len(set.paths)-1]
			set.paths = set.paths[:len(set.paths)-1]

			return &ret
		}
	}

	for idx, entry := range set.paths {
		if entry.expr.MatchString(path) {
			ret := entry.pattern
			set.paths[idx] = set.paths[len(set.paths)-1]
			set.paths = set.paths[:len(set.paths)-1]

			return &ret
		}
	}

	if globTokenRe.MatchString(path) {
		expr := globToRegex(path)

		for idx, entry := range set.paths {
			if !globTokenRe.MatchString(entry.pattern) && expr.MatchString(entry.pattern) {
				set.paths[idx] = set.paths[len(set.paths)-1]
				set.paths = set.paths[:len(set.paths)-1]

				ret := path

				return &ret
			}
		}
	}

	return nil
}

func (set *pathSet) add(pattern string) {
	expr := globToRegex(pattern)

	// Prune exact duplicates and non-glob entries subsumed by the new
	// pattern. Glob-vs-glob subsumption is not attempted because matching
	// a glob pattern string against another glob's regex does not reliably
	// indicate language inclusion.
	set.paths = slices.DeleteFunc(set.paths, func(existing apparmorPath) bool {
		if existing.pattern == pattern {
			return true
		}

		return !globTokenRe.MatchString(existing.pattern) &&
			expr.MatchString(existing.pattern)
	})

	set.paths = append(set.paths, apparmorPath{
		pattern: pattern,
		expr:    expr,
	})
}

func (set *pathSet) patterns() []string {
	if len(set.paths) == 0 {
		return nil
	}

	ret := make([]string, 0, len(set.paths))

	for _, entry := range set.paths {
		ret = append(ret, entry.pattern)
	}

	return ret
}
