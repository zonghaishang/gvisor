// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linux

import (
	"bytes"
	"fmt"
)

const (
	// UTSLen is the maximum length of strings contained in fields of
	// UtsName.
	UTSLen = 64
)

// UtsName represents struct utsname, the struct returned by uname(2).
//
// +marshal
type UtsName struct {
	Sysname    [65]byte // UTSLen + 1, go-marshal: array len must be literal.
	Nodename   [65]byte // UTSLen + 1
	Release    [65]byte // UTSLen + 1
	Version    [65]byte // UTSLen + 1
	Machine    [65]byte // UTSLen + 1
	Domainname [65]byte // UTSLen + 1
}

// utsNameString converts a UtsName entry to a string without NULs.
func utsNameString(s [UTSLen + 1]byte) string {
	// The NUL bytes will remain even in a cast to string. We must
	// explicitly strip them.
	return string(bytes.TrimRight(s[:], "\x00"))
}

func (u UtsName) String() string {
	return fmt.Sprintf("{Sysname: %s, Nodename: %s, Release: %s, Version: %s, Machine: %s, Domainname: %s}",
		utsNameString(u.Sysname), utsNameString(u.Nodename), utsNameString(u.Release),
		utsNameString(u.Version), utsNameString(u.Machine), utsNameString(u.Domainname))
}
