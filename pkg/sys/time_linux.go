// Copyright 2017 Capsule8, Inc.
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
	"golang.org/x/sys/unix"
)

var vdsoClockGettimeSym uintptr

func nanotime() int64

// CurrentMonotonicRaw is a convenience function that returns that current
// system raw monotonic clock as an integer.
var CurrentMonotonicRaw = func() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts)
	return ts.Nano()
}

func init() {
	var ok bool
	vdsoClockGettimeSym, ok = LookupKernelSymbol("__vdso_clock_gettime")
	if ok {
		CurrentMonotonicRaw = nanotime
	}
}
