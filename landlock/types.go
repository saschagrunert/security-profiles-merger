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

// Profile represents a Landlock ruleset for merge operations.
type Profile struct {
	// HandledAccessFS is the set of filesystem access rights handled by this
	// ruleset. Rights not listed here are not restricted.
	HandledAccessFS []FSAccessRight `json:"handledAccessFs,omitempty"`

	// HandledAccessNet is the set of network access rights handled by this
	// ruleset. Rights not listed here are not restricted.
	HandledAccessNet []NetAccessRight `json:"handledAccessNet,omitempty"`

	// PathRules defines filesystem access rules for specific path hierarchies.
	PathRules []PathRule `json:"pathRules,omitempty"`

	// NetRules defines network access rules for specific ports.
	NetRules []NetRule `json:"netRules,omitempty"`
}

// FSAccessRight represents a Landlock filesystem access right.
type FSAccessRight string

const (
	// FSAccessExecute allows executing a file.
	FSAccessExecute FSAccessRight = "execute"

	// FSAccessWriteFile allows writing to a file.
	FSAccessWriteFile FSAccessRight = "write_file"

	// FSAccessReadFile allows reading a file.
	FSAccessReadFile FSAccessRight = "read_file"

	// FSAccessReadDir allows reading a directory.
	FSAccessReadDir FSAccessRight = "read_dir"

	// FSAccessRemoveDir allows removing a directory.
	FSAccessRemoveDir FSAccessRight = "remove_dir"

	// FSAccessRemoveFile allows removing a file.
	FSAccessRemoveFile FSAccessRight = "remove_file"

	// FSAccessMakeChar allows creating a character device.
	FSAccessMakeChar FSAccessRight = "make_char"

	// FSAccessMakeDir allows creating a directory.
	FSAccessMakeDir FSAccessRight = "make_dir"

	// FSAccessMakeReg allows creating a regular file.
	FSAccessMakeReg FSAccessRight = "make_reg"

	// FSAccessMakeSock allows creating a socket.
	FSAccessMakeSock FSAccessRight = "make_sock"

	// FSAccessMakeFIFO allows creating a FIFO.
	FSAccessMakeFIFO FSAccessRight = "make_fifo"

	// FSAccessMakeSym allows creating a symbolic link.
	FSAccessMakeSym FSAccessRight = "make_sym"

	// FSAccessMakeBlock allows creating a block device.
	FSAccessMakeBlock FSAccessRight = "make_block"

	// FSAccessRefer allows linking or renaming across directories.
	FSAccessRefer FSAccessRight = "refer"

	// FSAccessTruncate allows truncating a file.
	FSAccessTruncate FSAccessRight = "truncate"

	// FSAccessIOCTLDev allows ioctl on device files.
	FSAccessIOCTLDev FSAccessRight = "ioctl_dev"

	// FSAccessResolveUnix allows resolving/connecting to pathname-based
	// UNIX domain sockets.
	FSAccessResolveUnix FSAccessRight = "resolve_unix"
)

// NetAccessRight represents a Landlock network access right.
type NetAccessRight string

const (
	// NetAccessBindTCP allows binding a TCP socket.
	NetAccessBindTCP NetAccessRight = "bind_tcp"

	// NetAccessConnectTCP allows connecting a TCP socket.
	NetAccessConnectTCP NetAccessRight = "connect_tcp"

	// NetAccessBindUDP allows binding a UDP socket.
	NetAccessBindUDP NetAccessRight = "bind_udp"

	// NetAccessConnectUDP allows connecting a UDP socket.
	NetAccessConnectUDP NetAccessRight = "connect_udp"

	// NetAccessSendtoUDP allows sending to a UDP socket via sendto/sendmsg.
	NetAccessSendtoUDP NetAccessRight = "sendto_udp"
)

// PathRule defines the access rights allowed for a specific path hierarchy.
type PathRule struct {
	// Path is the filesystem path hierarchy this rule applies to.
	Path string `json:"path"`

	// AccessFS is the set of filesystem access rights allowed under this path.
	AccessFS []FSAccessRight `json:"accessFs,omitempty"`
}

// NetRule defines the access rights allowed for a specific port.
type NetRule struct {
	// Port is the network port this rule applies to.
	Port uint16 `json:"port"`

	// AccessNet is the set of network access rights allowed for this port.
	AccessNet []NetAccessRight `json:"accessNet,omitempty"`
}
