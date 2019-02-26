// Copyright 2018 Capsule8, Inc.
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

package sys

import (
	"crypto/sha256"
	"strings"
)

// Historical note:
// procfs.FileSystem.ProcessContainerID was initially written to use a regex
// to determine whether a cgroup path was for a container:
//
// Docker cgroup paths may look like either of:
// - /docker/[CONTAINER_ID]
// - /kubepods/[...]/[CONTAINER_ID]
// - /system.slice/docker-[CONTAINER_ID].scope
//
// const cgroupContainerPattern = "^(/docker/|/kubepods/.*/|/system.slice/docker-)([[:xdigit:]]{64})(.scope|$)"
//
// I've elected to not continue using this method, because it is inherently
// fragile. We can see here that Docker has already changed its format at least
// once. It also fails to work for anything other than Docker. Other container
// environments are not accounted for. More frustratingly, LXC, for example,
// even allows runtime customization of cgroup paths.
//
// What does not appear to be so fragile is that container IDs always have a
// sha256 hash in them. So we're going to look for sha256 strings.

func isHexDigit(r rune) bool {
	if r >= '0' && r <= '9' {
		return true
	}
	if r >= 'A' && r <= 'F' {
		return true
	}
	if r >= 'a' && r <= 'f' {
		return true
	}
	return false
}

// sha256.Size is sha256 size in bytes. Hexadecimal representation doubles that
const sha256HexSize = sha256.Size * 2

func isSHA256(s string) bool {
	if len(s) != sha256HexSize {
		return false
	}
	for _, c := range s {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// ContainerID returns the ContainerID extracted from the given string. The
// string may simply be a container ID or it may be a full cgroup controller
// path with a container ID embedded in it. If the given string contains no
// discernable container ID, the return will be "".
func ContainerID(s string) string {
	paths := strings.Split(s, "/")
	for _, p := range paths {
		if isSHA256(p) {
			return p
		}
		if len(p) > sha256HexSize {
			// Does it start with a sha256?
			x := p[:sha256HexSize]
			if !isHexDigit(rune(p[sha256HexSize])) && isSHA256(x) {
				return x
			}
			// Does it end with a sha256?
			x = p[len(p)-sha256HexSize:]
			if !isHexDigit(rune(p[len(p)-sha256HexSize-1])) && isSHA256(x) {
				return x
			}
		}
	}
	return ""
}
