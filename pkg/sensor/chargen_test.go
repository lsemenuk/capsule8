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

package sensor

import (
	"context"
	"testing"
	"time"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeChargenEvent(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := newTestSubscription(t, sensor)

	sample := &perf.SampleRecord{}
	data := perf.TraceEventSampleData{
		"index":      uint64(928734),
		"characters": "character string",
	}
	i, err := s.decodeChargenEvent(sample, data)
	require.NotNil(t, i)
	require.NoError(t, err)
	e, ok := i.(ChargenTelemetryEvent)
	require.True(t, ok)

	ok = testCommonTelemetryEventData(t, sensor, e)
	require.True(t, ok)
	assert.Equal(t, data["index"], e.Index)
	assert.Equal(t, data["characters"], e.Characters)
}

func TestGenerateCharacters(t *testing.T) {
	type testCase struct {
		start, length uint64
		result        string
	}

	testCases := []testCase{
		{0, 5, " !\"#$"},
		{33, 10, "ABCDEFGHIJ"},
		{65, 4, "abcd"},
		{90, 7, "z{|}~ !"},
	}

	for _, tc := range testCases {
		s := generateCharacters(tc.start, tc.length)
		assert.Equal(t, tc.result, s)
	}
}

func verifyRegisterChargenEventFilter(t *testing.T, s *Subscription, count int) {
	if count > 0 {
		assert.Len(t, s.eventSinks, count)
	} else {
		assert.Len(t, s.status, -count)
		assert.Len(t, s.eventSinks, 0)
	}
}

func TestRegisterChargenEventFilter(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	// Invalid length should fail
	s := newTestSubscription(t, sensor)
	s.RegisterChargenEventFilter(0, nil)
	verifyRegisterChargenEventFilter(t, s, -1)

	s = newTestSubscription(t, sensor)
	s.RegisterChargenEventFilter(1<<16+1, nil)
	verifyRegisterChargenEventFilter(t, s, -1)

	// Invalid filter expression should fail
	e := expression.Equal(expression.Identifier("foo"), expression.Value("bar"))
	expr, err := expression.NewExpression(e)
	require.NotNil(t, expr)
	require.NoError(t, err)

	s = newTestSubscription(t, sensor)
	s.RegisterChargenEventFilter(32, expr)
	verifyRegisterChargenEventFilter(t, s, -1)

	// This should succeed
	s = newTestSubscription(t, sensor)
	s.RegisterChargenEventFilter(32, nil)
	verifyRegisterChargenEventFilter(t, s, 1)

	ctx, cancel := context.WithCancel(context.Background())
	s.Run(ctx, nil)
	time.Sleep(200 * time.Millisecond)
	cancel()
}
