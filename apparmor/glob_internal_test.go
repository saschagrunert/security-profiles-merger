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
	"fmt"
	"testing"
)

func TestGlobRegexCacheEviction(t *testing.T) {
	globRegexCache.Clear()
	globRegexCacheCount.Store(0)

	for idx := range maxGlobCacheEntries + 1 {
		globToRegex(fmt.Sprintf("/test/%d/*", idx))
	}

	if globRegexCacheCount.Load() > maxGlobCacheEntries {
		t.Error("cache count should have been reset after eviction")
	}
}

func TestGlobLiteralPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"no glob tokens", "/var/log/syslog", "/var/log/syslog"},
		{"trailing double star", "/var/log/**", "/var/log/"},
		{"mid path star", "/var/*/foo", "/var/"},
		{"leading double star", "**", ""},
		{"leading star", "*", ""},
		{"question mark no slash", "?foo", ""},
		{"brace at start", "{a,b}/path", ""},
		{"glob after root", "/*.log", "/"},
		{"empty pattern", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := globLiteralPrefix(test.pattern)
			if got != test.want {
				t.Errorf("globLiteralPrefix(%q) = %q, want %q",
					test.pattern, got, test.want)
			}
		})
	}
}
