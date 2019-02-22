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
	"sync"
	"sync/atomic"
)

var nextStubSourceID uint64

// StubEventSource is an event source implementation used as part of
// StubEventSourceController.
type StubEventSource struct {
	sourceID uint64 // Use the SourceID method to read this

	CloseCount     int
	DisableCount   int
	EnableCount    int
	SetFilterCount int
	Filter         string
	Enabled        bool
	Closed         bool
}

func newStubEventSource(attr EventAttr) *StubEventSource {
	newSource := &StubEventSource{}
	newSource.init(attr)
	return newSource
}

// Close terminates the event source.
func (s *StubEventSource) Close() error {
	s.CloseCount++
	s.Closed = true
	return nil
}

// Disable disables the event source without terminating it. The event source
// may be re-enabled. It is not an error to disable an already disabled source.
func (s *StubEventSource) Disable() error {
	s.DisableCount++
	s.Enabled = false
	return nil
}

// Enable enables the event source. It is not an error to enable an already
// enabled source.
func (s *StubEventSource) Enable() error {
	s.EnableCount++
	s.Enabled = true
	return nil
}

// SetFilter sets a filter for an event source. Using the empty string for the
// filter clears the filter.
func (s *StubEventSource) SetFilter(filter string) error {
	s.SetFilterCount++
	s.Filter = filter
	return nil
}

// SourceID returns a unique identifier for the EventSource.
func (s *StubEventSource) SourceID() uint64 {
	return s.sourceID
}

func (s *StubEventSource) init(attr EventAttr) {
	s.sourceID = atomic.AddUint64(&nextStubSourceID, 1)
	s.Enabled = !attr.Disabled
}

// StubEventSourceLeader is an event source implementation used as part of
// StubEventSourceController.
type StubEventSourceLeader struct {
	StubEventSource
	pid, cpu   int
	controller *StubEventSourceController
}

func newStubEventSourceLeader(attr EventAttr, pid, cpu int) *StubEventSourceLeader {
	newSource := &StubEventSourceLeader{
		pid: pid,
		cpu: cpu,
	}
	newSource.StubEventSource.init(attr)
	return newSource
}

// Close terminates the event source.
func (s *StubEventSourceLeader) Close() error {
	var err error
	if err = s.StubEventSource.Close(); err == nil && s.controller != nil {
		s.controller.lock.Lock()
		delete(s.controller.activeLeaders, s.sourceID)
		s.controller.lock.Unlock()
	}
	return err
}

// NewEventSource creates a new EventSource that is a member of the group that
// this EventSourceLeader leads.
func (s *StubEventSourceLeader) NewEventSource(
	attr EventAttr,
	flags uintptr,
) (EventSource, error) {
	return newStubEventSource(attr), nil
}

// Read retrieves the raw data available from the event source. The
// function will return nil if there is no data availble for reading;
// otherwise it will return a byte slice that contains the data from
// the source. The acquireBuffer function will be called to acquire the
// byte slice to read into. To avoid the creation of tiny, short-lived
// objects that will put pressure on GC, the acquireBuffer function
// will return a byte slice and an offset into the byte slice where the
// data should be written.
func (s *StubEventSourceLeader) Read(
	acquireBuffer func(size int) ([]byte, int),
) {
}

// StubEventSourceController is a stub implementation of EventSourceController
// intended primarily for use in testing EventMonitor.
type StubEventSourceController struct {
	wakeupChannel chan bool

	lock          sync.RWMutex
	activeLeaders map[uint64]*StubEventSourceLeader
}

// NewStubEventSourceController creates a new StubEventSourceController and
// initializes it for use.
func NewStubEventSourceController() *StubEventSourceController {
	return &StubEventSourceController{
		wakeupChannel: make(chan bool, 1),
		activeLeaders: make(map[uint64]*StubEventSourceLeader),
	}
}

// Close closes the EventSourceController, cleaning up any resources that it
// may have reserved for itself. The EventSourceController is no longer usable
// after this function completes.
func (c *StubEventSourceController) Close() {
	c.wakeupChannel = nil
	c.activeLeaders = nil
}

// NewEventSourceLeader creates a new event source as a group leader. Group
// leaders may or may not have event sources as children.
func (c *StubEventSourceController) NewEventSourceLeader(
	attr EventAttr,
	pid, cpu int,
	flags uintptr,
) (EventSourceLeader, error) {
	l := newStubEventSourceLeader(attr, pid, cpu)
	l.controller = c
	c.lock.Lock()
	c.activeLeaders[l.sourceID] = l
	c.lock.Unlock()
	return l, nil
}

// Wait pauses execution until events become available for processing.
// A list of cookies will be returned, one for each EventSourceLeader
// that is ready for processing. The order is undefined.
func (c *StubEventSourceController) Wait() ([]uint64, error) {
	select {
	case <-c.wakeupChannel:
	}
	return nil, nil
}

// Wakeup wakes up the controller if it is blocked in a wait state.
func (c *StubEventSourceController) Wakeup() {
	select {
	case c.wakeupChannel <- true:
	default:
	}
}
