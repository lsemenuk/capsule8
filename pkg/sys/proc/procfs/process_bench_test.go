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

package procfs

import "testing"

func BenchmarkProcessContainerID(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = fs.ProcessContainerID(111343); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessCommandLine(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = fs.ProcessCommandLine(405); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTaskControlGroups(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = fs.TaskControlGroups(111343, 111343); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTaskCWD(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = fs.TaskCWD(111343, 111343); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTaskStartTime(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = fs.TaskStartTime(111343, 111343); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTaskUniqueID(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	startTime, err := fs.TaskStartTime(405, 414)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fs.TaskUniqueID(405, 414, startTime)
	}
}

func BenchmarkWalkTasks(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	knownTasks := map[uint64]bool{
		uint64(1)<<32 | uint64(1):           false,
		uint64(405)<<32 | uint64(405):       false,
		uint64(405)<<32 | uint64(406):       false,
		uint64(405)<<32 | uint64(414):       false,
		uint64(111343)<<32 | uint64(111343): false,
	}

	walkFunc := func(tgid, pid int) bool {
		key := (uint64(tgid) << 32) | uint64(pid)
		knownTasks[key] = true
		return true
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = fs.WalkTasks(walkFunc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadTaskStatus(b *testing.B) {
	fs, err := NewFileSystem("testdata/proc")
	if err != nil {
		b.Fatal(err)
	}

	type status struct {
		Name   string   `Name`
		PID    int32    `Pid`
		TGID   int32    `Tgid`
		FDSize uint64   `FDSize`
		UID    []uint32 `Uid`
		GID    []uint32 `Gid`
	}

	var actualStatus status

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = fs.ReadTaskStatus(405, 406, &actualStatus); err != nil {
			b.Fatal(err)
		}
	}
}
