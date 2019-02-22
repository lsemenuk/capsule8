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

package expression

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValueTypeOf(t *testing.T) {
	testCases := []struct {
		v interface{}
		t ValueType
	}{
		{"string", ValueTypeString},
		{int8(8), ValueTypeSignedInt8},
		{int16(8), ValueTypeSignedInt16},
		{int32(8), ValueTypeSignedInt32},
		{int64(8), ValueTypeSignedInt64},
		{uint8(8), ValueTypeUnsignedInt8},
		{uint16(8), ValueTypeUnsignedInt16},
		{uint32(8), ValueTypeUnsignedInt32},
		{uint64(8), ValueTypeUnsignedInt64},
		{true, ValueTypeBool},
		{8.8, ValueTypeDouble},
		{time.Now(), ValueTypeTimestamp},

		// Obviously we cannot perform an exhaustive test of all types
		// that should map to ValueTypeUnspecified, but this will at
		// least get us coverage of that case.
		{make(chan interface{}), ValueTypeUnspecified},
	}
	for _, tc := range testCases {
		assert.Equalf(t, tc.t, ValueTypeOf(tc.v), "%#v", tc.v)
	}
}

func TestValueTypeIsInteger(t *testing.T) {
	goodTests := []ValueType{
		ValueTypeSignedInt8,
		ValueTypeSignedInt16,
		ValueTypeSignedInt32,
		ValueTypeSignedInt64,
		ValueTypeUnsignedInt8,
		ValueTypeUnsignedInt16,
		ValueTypeUnsignedInt32,
		ValueTypeUnsignedInt64,
	}
	for _, tc := range goodTests {
		assert.Truef(t, tc.IsInteger(),
			"test case: %#v", tc)
	}

	badTests := []ValueType{
		ValueTypeUnspecified,
		ValueTypeString,
		ValueTypeBool,
		ValueTypeDouble,
		ValueTypeTimestamp,
	}
	for _, tc := range badTests {
		assert.Falsef(t, tc.IsInteger(),
			"test case: %#v", tc)
	}
}

func TestValueTypeIsNumeric(t *testing.T) {
	goodTests := []ValueType{
		ValueTypeSignedInt8,
		ValueTypeSignedInt16,
		ValueTypeSignedInt32,
		ValueTypeSignedInt64,
		ValueTypeUnsignedInt8,
		ValueTypeUnsignedInt16,
		ValueTypeUnsignedInt32,
		ValueTypeUnsignedInt64,
		ValueTypeDouble,
		ValueTypeTimestamp,
	}
	for _, tc := range goodTests {
		assert.Truef(t, tc.IsNumeric(),
			"test case: %#v", tc)
	}

	badTests := []ValueType{
		ValueTypeUnspecified,
		ValueTypeString,
		ValueTypeBool,
	}
	for _, tc := range badTests {
		assert.Falsef(t, tc.IsNumeric(),
			"test case: %#v", tc)
	}
}
func TestValueTypeIsString(t *testing.T) {
	goodTests := []ValueType{
		ValueTypeString,
	}
	for _, tc := range goodTests {
		assert.Truef(t, tc.IsString(),
			"test case: %#v", tc)
	}

	badTests := []ValueType{
		ValueTypeUnspecified,
		ValueTypeSignedInt8,
		ValueTypeSignedInt16,
		ValueTypeSignedInt32,
		ValueTypeSignedInt64,
		ValueTypeUnsignedInt8,
		ValueTypeUnsignedInt16,
		ValueTypeUnsignedInt32,
		ValueTypeUnsignedInt64,
		ValueTypeBool,
		ValueTypeDouble,
		ValueTypeTimestamp,
	}
	for _, tc := range badTests {
		assert.Falsef(t, tc.IsString(),
			"test case: %#v", tc)
	}
}
