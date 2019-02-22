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

// +build !linux

package perf

import (
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var nextDefaultEventSourceID uint64

type defaultEventSource struct {
	sourceID uint64
}

func (s *defaultEventSource) Close() error {
	return unix.ENOSYS
}

func (s *defaultEventSource) Disable() error {
	return unix.ENOSYS
}

func (s *defaultEventSource) Enable() error {
	return unix.ENOSYS
}

func (s *defaultEventSource) SetFilter(filter string) error {
	return unix.ENOSYS
}

func (s *defaultEventSource) SourceID() uint64 {
	return s.sourceID
}

type defaultEventSourceLeader struct {
	defaultEventSource
}

func (s *defaultEventSourceLeader) NewEventSource(
	attr EventAttr,
	flags uintptr,
) (EventSource, error) {
	return &defaultEventSource{
		sourceID: atomic.AddUint64(&nextDefaultEventSourceID, 1),
	}, nil
}

func (s *defaultEventSourceLeader) Read(
	acquireBuffer func(size int) ([]byte, int),
) {
	// Do nothing
}

type defaultEventSourceController struct{}

func newDefaultEventSourceController(opts eventMonitorOptions) (EventSourceController, error) {
	return &defaultEventSourceController{}, nil
}

func (c *defaultEventSourceController) Close() {
	// Do nothing
}

func (c *defaultEventSourceController) NewEventSourceLeader(
	attr EventAttr,
	pid, cpu int,
	flags uintptr,
) (EventSourceLeader, error) {
	return &defaultEventSourceLeader{
		defaultEventSource{
			sourceID: atomic.AddUint64(&nextDefaultEventSourceID, 1),
		},
	}, nil
}

func (c *defaultEventSourceController) Wait() ([]uint64, error) {
	return nil, unix.ENOSYS
}

func (c *defaultEventSourceController) Wakeup() {
	// Do nothing
}

type defaultTimedEvent struct {
	c      chan struct{}
	ticker *time.Ticker
}

func newDefaultTimedEvent() (*defaultTimedEvent, error) {
	e := &defaultTimedEvent{
		c: make(chan struct{}, 1),
	}
	return e, nil
}

func (e *defaultTimedEvent) Close() {
	if e.c != nil {
		close(e.c)
		e.c = nil
	}
	if e.ticker != nil {
		e.ticker.Stop()
		e.ticker = nil
	}
}

func (e *defaultTimedEvent) Signal() {
	select {
	case e.c <- struct{}{}:
	default:
	}
}

func (e *defaultTimedEvent) Wait(timeout time.Duration) bool {
	if timeout < 0 {
		<-e.c
		return true
	}
	if timeout == 0 {
		select {
		case <-e.c:
			return true
		default:
		}
		return false
	}

	var result bool
	e.ticker = time.NewTicker(timeout)
	select {
	case <-e.c:
		result = true
	case <-e.ticker.C:
		result = false
	}
	e.ticker.Stop()
	e.ticker = nil
	return result
}
