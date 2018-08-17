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

package perf

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseTypeAndName(t *testing.T) {
	type testCase struct {
		s        string
		size     int
		isSigned bool

		dataType     int32
		dataTypeSize int
		dataLocSize  int
		arraySize    int
	}

	// These tests should return false, nil
	validTests := []testCase{
		testCase{"__data_loc char[] name", 4, true, TraceEventFieldTypeString, 1, 4, 0},
		testCase{"__data_loc long[] name", 4, true, TraceEventFieldTypeSignedInt64, 8, 4, 0},

		testCase{"short iii[4]", 8, true, TraceEventFieldTypeSignedInt16, 2, 0, 4},
		testCase{"short iii[NUM_PIDS]", 8, true, TraceEventFieldTypeSignedInt16, 2, 0, 4},
		testCase{"unknown_type x[8]", 32, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 8},

		testCase{"bool yesno", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"char x", 1, true, TraceEventFieldTypeSignedInt8, 1, 0, 0},
		testCase{"short x", 2, true, TraceEventFieldTypeSignedInt16, 2, 0, 0},
		testCase{"int x", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"long x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"long long x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"unsigned char x", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"unsigned short x", 2, false, TraceEventFieldTypeUnsignedInt16, 2, 0, 0},
		testCase{"unsigned int x", 4, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"unsigned long x", 8, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},
		testCase{"unsigned long long x", 8, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		testCase{"s8 x", 1, true, TraceEventFieldTypeSignedInt8, 1, 0, 0},
		testCase{"s16 x", 2, true, TraceEventFieldTypeSignedInt16, 2, 0, 0},
		testCase{"s32 x", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"s64 x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"u8 x", 1, true, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"u16 x", 2, true, TraceEventFieldTypeUnsignedInt16, 2, 0, 0},
		testCase{"u32 x", 4, true, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"u64 x", 8, true, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		testCase{"pid_t pid", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"const char *pointer", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"const char **pointer", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"enum color c", 4, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},

		testCase{"unknown_type x", 1, true, TraceEventFieldTypeSignedInt8, 1, 0, 0},
		testCase{"unknown_type x", 2, true, TraceEventFieldTypeSignedInt16, 2, 0, 0},
		testCase{"unknown_type x", 4, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"unknown_type x", 8, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"unknown_type x", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
		testCase{"unknown_type x", 2, false, TraceEventFieldTypeUnsignedInt16, 2, 0, 0},
		testCase{"unknown_type x", 4, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"unknown_type x", 8, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		// For ints with kernel misrepresented sizes
		testCase{"int x", 16, true, TraceEventFieldTypeSignedInt32, 4, 0, 0},
		testCase{"unsigned int x", 16, false, TraceEventFieldTypeUnsignedInt32, 4, 0, 0},
		testCase{"long x", 16, true, TraceEventFieldTypeSignedInt64, 8, 0, 0},
		testCase{"unsigned long x", 16, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 0},

		// Misrepresented array sizes
		testCase{"u64 mismatch[6]", 24, false, TraceEventFieldTypeUnsignedInt64, 8, 0, 3},
	}
	for _, tc := range validTests {
		field := traceEventField{
			Size:     tc.size,
			IsSigned: tc.isSigned,
		}
		skip, err := field.parseTypeAndName(tc.s)
		assert(t, err == nil, "unexpected error for %s", tc.s)
		assert(t, skip == false, "unexpected skip for %s", tc.s)

		assert(t, field.dataType == tc.dataType, "bad dataType for %s (got %d)", tc.s, field.dataType)
		assert(t, field.dataTypeSize == tc.dataTypeSize, "bad dataTypeSize for %s (got %d)", tc.s, field.dataTypeSize)
		assert(t, field.dataLocSize == tc.dataLocSize, "bad dataLocSize for %s (got %d)", tc.s, field.dataLocSize)
		assert(t, field.arraySize == tc.arraySize, "bad arraySize for %s (got %d)", tc.s, field.arraySize)
	}

	// These tests should return true, nil
	skipTests := []testCase{
		testCase{"__data_loc struct foo[] bar", 32, false, 0, 0, 0, 0},
		testCase{"struct foo bar", 32, false, 0, 0, 0, 0},
		testCase{"union foo bar", 8, false, 0, 0, 0, 0},
		testCase{"gid_t groups[NGROUP]", 64, true, 0, 0, 0, 0},
	}
	for _, tc := range skipTests {
		field := traceEventField{
			Size:     tc.size,
			IsSigned: tc.isSigned,
		}
		skip, err := field.parseTypeAndName(tc.s)
		assert(t, err == nil, "unexpected error for %s", tc.s)
		assert(t, skip == true, "unexpected no-skip for %s", tc.s)
	}

	// These tests should return an error
	invalidTests := []testCase{
		testCase{"__data_loc char name", 1, true, 0, 0, 0, 0},
		testCase{"char[] name", 1, true, 0, 0, 0, 0},
		testCase{"char [", 1, true, 0, 0, 0, 0},
		testCase{"bool", 1, false, TraceEventFieldTypeUnsignedInt8, 1, 0, 0},
	}
	for _, tc := range invalidTests {
		field := traceEventField{
			Size:     tc.size,
			IsSigned: tc.isSigned,
		}
		_, err := field.parseTypeAndName(tc.s)
		assert(t, err != nil, "unexpected success %s", tc.s)
	}
}

func TestGetTraceEventFormat(t *testing.T) {
	var err error

	_, _, err = getTraceEventFormat("testdata", "nonexistent")
	assert(t, err != nil, "unexpected nil error result for non-existent file")

	invalidTests := []string{
		"id", "field", "offset", "size", "signed", "type",
	}
	for _, s := range invalidTests {
		name := fmt.Sprintf("invalid/invalid_%s", s)
		_, _, err = getTraceEventFormat("testdata", name)
		assert(t, err != nil, "unexpected nil error result for %s", name)
	}

	expectedFormat := TraceEventFormat{
		traceEventField{
			FieldName:    "common_type",
			TypeName:     "unsigned short",
			Offset:       0,
			Size:         2,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt16,
			dataTypeSize: 2,
		},
		traceEventField{
			FieldName:    "common_flags",
			TypeName:     "unsigned char",
			Offset:       2,
			Size:         1,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt8,
			dataTypeSize: 1,
		},
		traceEventField{
			FieldName:    "common_preempt_count",
			TypeName:     "unsigned char",
			Offset:       3,
			Size:         1,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt8,
			dataTypeSize: 1,
		},
		traceEventField{
			FieldName:    "common_pid",
			TypeName:     "int",
			Offset:       4,
			Size:         4,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeSignedInt32,
			dataTypeSize: 4,
		},
		traceEventField{
			FieldName:    "name",
			TypeName:     "char",
			Offset:       8,
			Size:         4,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeString,
			dataTypeSize: 1,
			dataLocSize:  4,
		},
		traceEventField{
			FieldName:    "longs",
			TypeName:     "long",
			Offset:       12,
			Size:         4,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeSignedInt64,
			dataTypeSize: 8,
			dataLocSize:  4,
		},
		// Skips are turned into arrays of bytes
		traceEventField{
			FieldName:    "signed_skip",
			TypeName:     "gid_t",
			Offset:       16,
			Size:         64,
			IsSigned:     true,
			dataType:     TraceEventFieldTypeSignedInt8,
			dataTypeSize: 1,
			arraySize:    64,
		},
		traceEventField{
			FieldName:    "unsigned_skip",
			TypeName:     "gid_t",
			Offset:       80,
			Size:         64,
			IsSigned:     false,
			dataType:     TraceEventFieldTypeUnsignedInt8,
			dataTypeSize: 1,
			arraySize:    64,
		},
	}

	id, actualFormat, err := getTraceEventFormat("testdata", "valid/valid")
	ok(t, err)
	equals(t, uint16(31337), id)
	equals(t, expectedFormat, actualFormat)
}

func TestDecodeDataType(t *testing.T) {
	type testCase struct {
		dataType      int32
		rawData       []byte
		expectedValue interface{}
		expectedErr   bool
	}
	testCases := []testCase{
		testCase{
			dataType:      TraceEventFieldTypeString,
			rawData:       nil,
			expectedValue: nil,
			expectedErr:   true,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt8,
			rawData:       []byte{8},
			expectedValue: int8(8),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt16,
			rawData:       []byte{0x34, 0x12},
			expectedValue: int16(0x1234),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt32,
			rawData:       []byte{0x11, 0x22, 0x33, 0x44},
			expectedValue: int32(0x44332211),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeSignedInt64,
			rawData:       []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11},
			expectedValue: int64(0x1122334455667788),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt8,
			rawData:       []byte{0x56},
			expectedValue: uint8(0x56),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt16,
			rawData:       []byte{0x34, 0x12},
			expectedValue: uint16(0x1234),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt32,
			rawData:       []byte{0x11, 0x22, 0x33, 0x44},
			expectedValue: uint32(0x44332211),
			expectedErr:   false,
		},
		testCase{
			dataType:      TraceEventFieldTypeUnsignedInt64,
			rawData:       []byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89},
			expectedValue: uint64(0x8978675645342312),
			expectedErr:   false,
		},
		testCase{
			dataType:      29384756,
			rawData:       nil,
			expectedValue: nil,
			expectedErr:   true,
		},
	}
	for _, tc := range testCases {
		actualValue, err := decodeDataType(tc.dataType, tc.rawData)
		if tc.expectedErr {
			assert(t, err != nil, "expected error for dataType %d", tc.dataType)
		} else {
			assert(t, err == nil, "unexpected error for dataType %d", tc.dataType)
		}
		assert(t, reflect.DeepEqual(tc.expectedValue, actualValue),
			"Result does not match for dataType %d\n\n\texp: %#v\n\n\tgot: %#v",
			tc.dataType, tc.expectedValue, actualValue)
	}
}

func TestDecodeRawData(t *testing.T) {
	rawData := []byte{
		0x1c, 0x00, 0x06, 0x00, // name4
		0x22, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, // name8
		0x11, 0x22, 0x33, 0x44, // pid
		0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, // args
		0x28, 0x00, 0x04, 0x00, // foo

		'N', 'A', 'M', 'E', '4', 0,
		'N', 'A', 'M', 'E', '8', 0,
		0x11, 0x22, 0x33, 0x44,
	}

	format := TraceEventFormat{
		traceEventField{
			FieldName:    "name4",
			Offset:       0,
			dataType:     TraceEventFieldTypeString,
			dataTypeSize: 1,
			dataLocSize:  4,
		},
		traceEventField{
			FieldName:    "name8",
			Offset:       4,
			dataType:     TraceEventFieldTypeString,
			dataTypeSize: 1,
			dataLocSize:  8,
		},
		traceEventField{
			FieldName: "pid",
			Offset:    12,
			dataType:  TraceEventFieldTypeSignedInt32,
		},
		traceEventField{
			FieldName:    "args",
			Offset:       16,
			dataType:     TraceEventFieldTypeUnsignedInt32,
			dataTypeSize: 4,
			arraySize:    2,
		},
		traceEventField{
			FieldName:    "foo",
			Offset:       24,
			dataType:     TraceEventFieldTypeUnsignedInt8,
			dataTypeSize: 1,
			dataLocSize:  4,
		},
	}

	e := TraceEventSampleData{
		"name4": "NAME4",
		"name8": "NAME8",
		"pid":   int32(0x44332211),
		"args":  []interface{}{uint32(0x01010101), uint32(0x02020202)},
		"foo":   []interface{}{uint8(0x11), uint8(0x22), uint8(0x33), uint8(0x44)},
	}

	data, err := format.DecodeRawData(rawData)
	ok(t, err)
	equals(t, e, data)

	format = TraceEventFormat{
		traceEventField{
			FieldName:   "error",
			dataLocSize: 16,
		},
	}
	_, err = format.DecodeRawData(rawData)
	assert(t, err != nil, "Expected error")

	format = TraceEventFormat{
		traceEventField{
			FieldName: "error",
			dataType:  TraceEventFieldTypeString,
		},
	}
	_, err = format.DecodeRawData(rawData)
	assert(t, err != nil, "Expected error")

	format = TraceEventFormat{
		traceEventField{
			FieldName: "error",
			dataType:  TraceEventFieldTypeString,
			arraySize: 4,
		},
	}
	_, err = format.DecodeRawData(rawData)
	assert(t, err != nil, "Expected error")
}
