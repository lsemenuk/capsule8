// Copyright 2019 Capsule8, Inc.
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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFieldNotSetError(t *testing.T) {
	// Just ensure that we get a non-zero length string back. There's
	// nothing more to really check, but it'd be good to know that it's
	// not going to crash if it gets used in a production code path.
	err := FieldNotSet{}
	assert.NotEmpty(t, err.Error())

	err = FieldNotSet{Name: "foo"}
	assert.NotEmpty(t, err.Error())
}

func TestFieldTypeMismatch(t *testing.T) {
	// Just ensure that we get a non-zero length string back. There's
	// nothing more to really check, but it'd be good to know that it's
	// not going to crash if it gets used in a production code path.
	err := FieldTypeMismatch{}
	assert.NotEmpty(t, err.Error())

	err = FieldTypeMismatch{Name: "foo"}
	assert.NotEmpty(t, err.Error())

	err = FieldTypeMismatch{
		Name:         "",
		ExpectedType: ValueTypeString,
		ActualType:   ValueTypeSignedInt16,
	}
	assert.NotEmpty(t, err.Error())
}

func TestFieldValueMap(t *testing.T) {
	values := FieldValueMap{
		"s":   "string",
		"s8":  int8(8),
		"s16": int16(8),
		"s32": int32(8),
		"s64": int64(8),
		"u8":  uint8(8),
		"u16": uint16(8),
		"u32": uint32(8),
		"u64": uint64(8),
		"b":   true,
		"d":   float64(8),
		"t":   time.Unix(8, 8),
	}

	testCases := []struct {
		fn   string
		name string
	}{
		{"GetString", "s"},
		{"GetSignedInt8", "s8"},
		{"GetSignedInt16", "s16"},
		{"GetSignedInt32", "s32"},
		{"GetSignedInt64", "s64"},
		{"GetUnsignedInt8", "u8"},
		{"GetUnsignedInt16", "u16"},
		{"GetUnsignedInt32", "u32"},
		{"GetUnsignedInt64", "u64"},
		{"GetBool", "b"},
		{"GetDouble", "d"},
		{"GetTimestamp", "t"},
	}

	valuesValue := reflect.ValueOf(values)
	for _, tc := range testCases {
		m := valuesValue.MethodByName(tc.fn)
		r := m.Call([]reflect.Value{reflect.ValueOf(tc.name)})

		if !r[1].IsNil() {
			err := r[1].Interface().(error)
			assert.NoError(t, err, tc.fn)
		} else {
			assert.Equal(t, values[tc.name], r[0].Interface(), tc.fn)
		}

		r = m.Call([]reflect.Value{reflect.ValueOf("foo")})
		if assert.False(t, r[1].IsNil()) {
			assert.IsType(t, FieldNotSet{}, r[1].Interface())
		}

		expectedType := ValueTypeOf(values[tc.name])
		for k, v := range values {
			if k == tc.name {
				continue
			}
			r = m.Call([]reflect.Value{reflect.ValueOf(k)})
			if assert.False(t, r[1].IsNil()) {
				if assert.IsType(t, FieldTypeMismatch{}, r[1].Interface()) {
					err := r[1].Interface().(FieldTypeMismatch)
					assert.Equal(t, k, err.Name)
					assert.Equal(t, expectedType, err.ExpectedType)
					assert.Equal(t, ValueTypeOf(v), err.ActualType)
				}
			}
		}
	}
}
