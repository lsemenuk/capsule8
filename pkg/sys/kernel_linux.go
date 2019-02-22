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
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io/ioutil"
	"sync"
	"syscall"
	"unsafe"
)

var (
	initVDSO sync.Once

	vdsoSymbols      map[string]uintptr
	linuxVersionCode uint32
)

func initializeVDSO() {
	initVDSO.Do(func() { readVDSO() })
}

// KernelVersionCode returns a single integer that encodes the version of the
// running kernel. This code should be treated as having arbitrary meaning.
func KernelVersionCode() uint32 {
	initializeVDSO()
	return linuxVersionCode
}

// LookupKernelSymbol returns the address of a symbol from the kernel's vDSO
// symbol table. The address has been relocated to the load offset in the
// current process and may be called are accessed directly by the returned
// address.
func LookupKernelSymbol(name string) (addr uintptr, ok bool) {
	initializeVDSO()
	addr, ok = vdsoSymbols[name]
	return
}

type vdsoReader struct {
	base uintptr
}

func (r *vdsoReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, syscall.EINVAL
	}

	var slice = struct {
		addr uintptr
		len  int
		cap  int
	}{r.base + uintptr(off), len(p), len(p)}
	b := *(*[]byte)(unsafe.Pointer(&slice))
	copy(p, b)

	return len(p), nil
}

func getauxval(x uintptr) (uintptr, error) {
	b, err := ioutil.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}

	var k, v uint64
	reader := bytes.NewReader(b)
	for reader.Len() >= 16 {
		if err = binary.Read(reader, binary.LittleEndian, &k); err != nil {
			return 0, err
		}
		if err = binary.Read(reader, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		if uintptr(k) == x {
			return uintptr(v), nil
		}
	}

	return 0, syscall.ENOENT
}

func readVDSO() error {
	vdsoSymbols = make(map[string]uintptr)
	vdsoBase, err := getauxval(AT_SYSINFO_EHDR)
	if err != nil || vdsoBase == 0 {
		return err
	}

	reader := &vdsoReader{base: vdsoBase}
	f, err := elf.NewFile(reader)
	if err != nil {
		return err
	}
	defer f.Close()

	var loadOffset uintptr
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			loadOffset = vdsoBase + uintptr(p.Off-p.Vaddr)
		case elf.PT_NOTE:
			readLinuxVersionCode(p)
		}
	}

	if loadOffset != 0 {
		var syms []elf.Symbol
		if syms, err = f.DynamicSymbols(); err == nil {
			for _, sym := range syms {
				if sym.Name != "" && sym.Value != 0 {
					vdsoSymbols[sym.Name] =
						loadOffset + uintptr(sym.Value)
				}
			}
		}
	}

	return nil
}

func readLinuxVersionCode(p *elf.Prog) {
	r := p.Open()
	for {
		var (
			err                   error
			descsz, namesz, ntype uint32
		)

		if err = binary.Read(r, binary.LittleEndian, &namesz); err != nil {
			return
		}
		if err = binary.Read(r, binary.LittleEndian, &descsz); err != nil {
			return
		}
		if err = binary.Read(r, binary.LittleEndian, &ntype); err != nil {
			return
		}

		n := (namesz + 3) & ^uint32(3)
		b := make([]byte, n)
		if err = binary.Read(r, binary.LittleEndian, b); err != nil {
			return
		}
		name := string(b[:namesz-1])

		n = (descsz + 3) & ^uint32(3)
		b = make([]byte, n)
		if err = binary.Read(r, binary.LittleEndian, b); err != nil {
			return
		}

		if name == "Linux" && descsz == 4 && ntype == 0 {
			linuxVersionCode = *(*uint32)(unsafe.Pointer(&b[0]))
		}
	}
}
