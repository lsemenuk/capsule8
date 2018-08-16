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
	"testing"
)

func TestSafeUInt64Map(t *testing.T) {
	sm := safeUInt64Map{}
	sm.removeInPlace([]uint64{1, 2, 3, 4, 5})
	equals(t, 0, len(sm.getMap()))

	sm.remove([]uint64{1, 2, 3, 4, 5})
	equals(t, 0, len(sm.getMap()))

	m := newUInt64Map()
	m[1] = 1001
	m[2] = 1002
	m[3] = 1003
	sm = safeUInt64Map{}
	sm.updateInPlace(m)
	equals(t, 3, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm.removeInPlace([]uint64{2})
	delete(m, 2)
	equals(t, 2, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm = safeUInt64Map{}
	wg := sync.WaitGroup{}
	for i := uint64(0); i < 8; i++ {
		wg.Add(1)
		go func(i uint64) {
			for x := uint64(0); x < 1000; x++ {
				switch x % 3 {
				case 0:
					lm := newUInt64Map()
					lm[i] = x
					sm.update(lm)
				case 1:
					lm := sm.getMap()
					_, _ = lm[i]
				case 2:
					ids := []uint64{(i + x) % 8}
					sm.remove(ids)
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestSafeEventAttrMap(t *testing.T) {
	sm := safeEventAttrMap{}
	sm.removeInPlace([]uint64{1, 2, 3, 4, 5})
	equals(t, 0, len(sm.getMap()))

	sm.remove([]uint64{1, 2, 3, 4, 5})
	equals(t, 0, len(sm.getMap()))

	m := newEventAttrMap()
	m[1] = EventAttr{Type: 1001}
	m[2] = EventAttr{Type: 1002}
	m[3] = EventAttr{Type: 1003}
	sm = safeEventAttrMap{}
	sm.updateInPlace(m)
	equals(t, 3, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm.removeInPlace([]uint64{2})
	delete(m, 2)
	equals(t, 2, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm = safeEventAttrMap{}
	wg := sync.WaitGroup{}
	for i := uint64(0); i < 8; i++ {
		wg.Add(1)
		go func(i uint64) {
			for x := uint64(0); x < 1000; x++ {
				switch x % 3 {
				case 0:
					lm := newEventAttrMap()
					lm[i] = EventAttr{Type: uint32(x)}
					sm.update(lm)
				case 1:
					lm := sm.getMap()
					_, _ = lm[i]
				case 2:
					ids := []uint64{(i + x) % 8}
					sm.remove(ids)
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestSafeRegisteredEventMap(t *testing.T) {
	sm := safeRegisteredEventMap{}
	_, f := sm.lookup(8)
	equals(t, false, f)

	sm.removeInPlace(8)
	equals(t, 0, len(sm.getMap()))

	sm.remove(8)
	equals(t, 0, len(sm.getMap()))

	m := newRegisteredEventMap()
	m[1] = &registeredEvent{id: 1001}
	m[2] = &registeredEvent{id: 1002}
	m[3] = &registeredEvent{id: 1003}
	sm = safeRegisteredEventMap{}
	for k, v := range m {
		sm.insertInPlace(k, v)
	}
	equals(t, 3, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm.removeInPlace(2)
	delete(m, 2)
	equals(t, 2, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm = safeRegisteredEventMap{}
	wg := sync.WaitGroup{}
	for i := uint64(0); i < 8; i++ {
		wg.Add(1)
		go func(i uint64) {
			for x := uint64(0); x < 1000; x++ {
				switch x % 3 {
				case 0:
					re := &registeredEvent{id: x}
					sm.insert(i, re)
				case 1:
					_, _ = sm.lookup(i)
				case 2:
					sm.remove((i + x) % 8)
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

type dummyPerfGroupLeaderEventSourceLeader struct {
	id uint64
}

func (s *dummyPerfGroupLeaderEventSourceLeader) Close() error {
	return nil
}

func (s *dummyPerfGroupLeaderEventSourceLeader) Disable() error {
	return nil
}

func (s *dummyPerfGroupLeaderEventSourceLeader) Enable() error {
	return nil
}

func (s *dummyPerfGroupLeaderEventSourceLeader) SetFilter(f string) error {
	return nil
}

func (s *dummyPerfGroupLeaderEventSourceLeader) SourceID() uint64 {
	return s.id
}

func (s *dummyPerfGroupLeaderEventSourceLeader) NewEventSource(
	attr EventAttr,
	flags uintptr,
) (EventSource, error) {
	return nil, nil
}

func (s *dummyPerfGroupLeaderEventSourceLeader) Read(
	attrMap map[uint64]EventAttr,
	f func(Sample, error),
) {
	// do nothing
}

func TestSafePerfGroupLeaderMap(t *testing.T) {
	sm := safePerfGroupLeaderMap{}
	_, p := sm.lookup(8)
	equals(t, false, p)

	sm.removeInPlace(map[uint64]struct{}{1: struct{}{}, 2: struct{}{}, 3: struct{}{}})
	equals(t, 0, len(sm.getMap()))

	sm.remove(map[uint64]struct{}{1: struct{}{}, 2: struct{}{}, 3: struct{}{}})
	equals(t, 0, len(sm.getMap()))

	m := newPerfGroupLeaderMap()
	m[1] = &perfGroupLeader{source: &dummyPerfGroupLeaderEventSourceLeader{id: 1}}
	m[2] = &perfGroupLeader{source: &dummyPerfGroupLeaderEventSourceLeader{id: 2}}
	m[3] = &perfGroupLeader{source: &dummyPerfGroupLeaderEventSourceLeader{id: 3}}
	sm = safePerfGroupLeaderMap{}
	var leaders []*perfGroupLeader
	for _, v := range m {
		leaders = append(leaders, v)
	}
	sm.updateInPlace(leaders)
	equals(t, 3, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm.removeInPlace(map[uint64]struct{}{2: struct{}{}})
	delete(m, 2)
	equals(t, 2, len(sm.getMap()))
	equals(t, m, sm.getMap())

	sm = safePerfGroupLeaderMap{}
	wg := sync.WaitGroup{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			for x := uint64(0); x < 1000; x++ {
				switch x % 3 {
				case 0:
					s := &dummyPerfGroupLeaderEventSourceLeader{id: x}
					l := &perfGroupLeader{source: s}
					sm.update([]*perfGroupLeader{l})
				case 1:
					_, _ = sm.lookup(x)
				case 2:
					sm.remove(map[uint64]struct{}{x: struct{}{}})
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestSafeTraceEventFormatMap(t *testing.T) {
	sm := safeTraceEventFormatMap{}
	sm.removeInPlace(5)
	equals(t, 0, len(sm.getMap()))

	sm.remove(5)
	equals(t, 0, len(sm.getMap()))

	sm = safeTraceEventFormatMap{}
	m := make(TraceEventFormat, 0)
	sm.insertInPlace(1001, m)
	equals(t, 1, len(sm.getMap()))
	format, found := sm.lookup(1001)
	equals(t, m, format)
	equals(t, true, found)

	sm.removeInPlace(1001)
	equals(t, 0, len(sm.getMap()))
	format, found = sm.lookup(1001)
	equals(t, TraceEventFormat(nil), format)
	equals(t, false, found)

	sm = safeTraceEventFormatMap{}
	wg := sync.WaitGroup{}
	for i := uint16(0); i < 8; i++ {
		wg.Add(1)
		go func(i uint16) {
			for x := uint16(0); x < 1000; x++ {
				switch x % 3 {
				case 0:
					sm.insert(x, make(TraceEventFormat, 0))
				case 1:
					lm := sm.getMap()
					_, _ = lm[i]
				case 2:
					sm.remove((i + x) % 8)
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}
