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

package perf

import (
	"time"
)

// EventSource defines the interface for an event source.
type EventSource interface {
	// Close terminates the event source.
	Close() error

	// Disable disables the event source without terminating it. The event
	// source may be re-enabled. It is not an error to disable an already
	// disabled source.
	Disable() error

	// Enable enables the event source. It is not an error to enable an
	// already enabled source.
	Enable() error

	// SetFilter sets a filter for an event source. Using the empty string
	// for the filter clears the filter.
	SetFilter(filter string) error

	// SourceID returns a unique identifier for the EventSource.
	SourceID() uint64
}

// EventSourceLeader defines the interface for an event source that is also a
// group leader.
type EventSourceLeader interface {
	EventSource

	// NewEventSource creates a new EventSource that is a member of the
	// group that this EventSourceLeader leads.
	NewEventSource(attr EventAttr, flags uintptr) (EventSource, error)

	// Read retrieves the raw data available from the event source. The
	// function will return nil if there is no data availble for reading;
	// otherwise it will return a byte slice that contains the data from
	// the source. The acquireBuffer function will be called to acquire the
	// byte slice to read into. To avoid the creation of tiny, short-lived
	// objects that will put pressure on GC, the acquireBuffer function
	// will return a byte slice and an offset into the byte slice where the
	// data should be written.
	Read(acquireBuffer func(size int) ([]byte, int))
}

// EventSourceController defines the interface with which EventMonitor will
// obtain event information.
type EventSourceController interface {
	// Close closes the EventSourceController, cleaning up any resources
	// that it may have reserved for itself. The EventSourceController is
	// no longer usable after this function completes.
	Close()

	// NewEventSourceLeader creates a new event source as a group leader.
	// Group leaders may or may not have event sources as children.
	NewEventSourceLeader(attr EventAttr, pid, cpu int, flags uintptr) (EventSourceLeader, error)

	// Wait pauses execution until events become available for processing.
	// A list of source IDs will be returned, one for each EventSourceLeader
	// that is ready for processing. The order is undefined.
	Wait() ([]uint64, error)

	// Wakeup wakes up the controller if it is blocked in a wait state.
	Wakeup()
}

// TimedEvent defines the interface for an object implementing a dual signaling
// mechanism: explicit wake-up or timeout. This is necessary because the Go
// runtime does not support anything of the kind, instead forcing the use of
// channels to achieve the same effect. Unfortunately this method also requires
// several new object allocations every time it is employed or it gets overly
// complicated. This interface exists to abstract away the ugliness and allow
// alternate implementations that may be better but not available on all
// platforms. The actual desired behavior is exactly that of a timed wait on a
// cond with a mutex (the POSIX version would be pthread_cond_timedwait). Since
// we cannot work atomically with a mutex and wait, we have to employ alternate
// behavior as described for each of the interfaces methods.
type TimedEvent interface {
	// Close cleans up any resources used by the TimedEvent. The TimedEvent
	// becomes unusable after it has been closed.
	Close()

	// Signal signals a TimedEvent. The signal remains set even if there is
	// not a waiter. The next wait will wake immediately. This behavior is
	// needed because we cannot work with a mutex to avoid race conditions.
	// Normally we would lock the mutex, signal, then unlock the mutex.
	Signal()

	// Wait for the TimedEvent to be signaled or wait for the specified
	// timeout to elapse, whichever happens first. A negative duration
	// waits forever. A duration of 0 times out immediately. The return is
	// true if the Wait returned because the TimedEvent was signalled;
	// otherwise, it returns false to indicate a timeout occurred. The
	// event may already be signalled on entry, in which case the Wait will
	// return immediately. This behavior is needed because we cannot work
	// with a mutex to avoid race conditions. Normally the mutex would be
	// locked when Wait is called, and Wait would atomically unlock the
	// mutex while waiting, locking it again once woken up.
	Wait(timeout time.Duration) bool
}
