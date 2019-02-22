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

// +build !linux

package sys

// KernelVersionCode returns a single integer that encodes the version of the
// running kernel. This code should be treated as having arbitrary meaning.
func KernelVersionCode() uint32 {
	major, minor, sublevel := KernelVersion()
	return (uint32(major) << 16) | (uint32(minor) << 8) | uint32(sublevel)
}

// LookupKernelSymbol returns the address of a symbol from the kernel's vDSO
// symbol table. The address has been relocated to the load offset in the
// current process and may be called are accessed directly by the returned
// address.
func LookupKernelSymbol(name string) (addr uintptr, ok bool) {
	return
}
