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

package landlock

import (
	"fmt"
	"strings"
)

// String returns a human-readable representation of the profile.
func (p Profile) String() string {
	var parts []string

	if len(p.HandledAccessFS) > 0 {
		parts = append(parts, "fs:"+joinFS(p.HandledAccessFS))
	}

	if len(p.HandledAccessNet) > 0 {
		parts = append(parts, "net:"+joinNet(p.HandledAccessNet))
	}

	for _, rule := range p.PathRules {
		parts = append(parts, rule.String())
	}

	for _, rule := range p.NetRules {
		parts = append(parts, rule.String())
	}

	return fmt.Sprintf("Profile{%s}", strings.Join(parts, " "))
}

// String returns a human-readable representation of the path rule.
func (r PathRule) String() string {
	return fmt.Sprintf("%s(%s)", r.Path, joinFS(r.AccessFS))
}

// String returns a human-readable representation of the network rule.
func (r NetRule) String() string {
	return fmt.Sprintf(":%d(%s)", r.Port, joinNet(r.AccessNet))
}

func joinFS(rights []FSAccessRight) string {
	strs := make([]string, len(rights))

	for idx, r := range rights {
		strs[idx] = string(r)
	}

	return strings.Join(strs, ",")
}

func joinNet(rights []NetAccessRight) string {
	strs := make([]string, len(rights))

	for idx, r := range rights {
		strs[idx] = string(r)
	}

	return strings.Join(strs, ",")
}
