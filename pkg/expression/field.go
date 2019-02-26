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
	"fmt"
	"time"
)

// FieldValueGetter is an interface that can be implemented to allow for
// customizing how expression evaluation retrieves values for field references
// on demand.
type FieldValueGetter interface {
	GetString(name string) (string, error)
	GetSignedInt8(name string) (int8, error)
	GetSignedInt16(name string) (int16, error)
	GetSignedInt32(name string) (int32, error)
	GetSignedInt64(name string) (int64, error)
	GetUnsignedInt8(name string) (uint8, error)
	GetUnsignedInt16(name string) (uint16, error)
	GetUnsignedInt32(name string) (uint32, error)
	GetUnsignedInt64(name string) (uint64, error)
	GetBool(name string) (bool, error)
	GetDouble(name string) (float64, error)
	GetTimestamp(name string) (time.Time, error)
}

// FieldNotSet is an error type that can be returned by a FieldValueGetter
// method when the field is not set, in which case the evaluator will treat
// the value is NULL.
type FieldNotSet struct {
	// Name is the name of the field that is not set.
	Name string
}

func (fns FieldNotSet) Error() string {
	return fmt.Sprintf("field %s is not set", fns.Name)
}

// FieldTypeMismatch is an error type that can be returned by a FieldValueGetter
// method when the field is set, but its value type is not what is requested.
type FieldTypeMismatch struct {
	// Name is the name of the field that has a type mismatch.
	Name string

	// ExpectedType is the type that was requested.
	ExpectedType ValueType

	// ActualType is the type that was present.
	ActualType ValueType
}

func (ftm FieldTypeMismatch) Error() string {
	return fmt.Sprintf("Data type mismatch for %q (expected %s; got %s)",
		ftm.Name,
		ValueTypeStrings[ftm.ExpectedType],
		ValueTypeStrings[ftm.ActualType])
}

// FieldTypeMap is a mapping of types for field names/identifiers
type FieldTypeMap map[string]ValueType

// FieldValueMap is a mapping of values for field names/identifiers.
type FieldValueMap map[string]interface{}

func (m FieldValueMap) getValue(
	name string,
	expectedType ValueType,
) (i interface{}, err error) {
	var ok bool
	if i, ok = m[name]; ok {
		actualType := ValueTypeOf(i)
		if expectedType != actualType {
			err = FieldTypeMismatch{
				Name:         name,
				ExpectedType: expectedType,
				ActualType:   actualType,
			}
		}
	} else {
		err = FieldNotSet{Name: name}
	}
	return
}

// GetString returns the string value set for the requested field name.
func (m FieldValueMap) GetString(name string) (v string, err error) {
	i, err := m.getValue(name, ValueTypeString)
	if err == nil {
		v = i.(string)
	}
	return
}

// GetSignedInt8 returns the signed 8-bit integer value set for the requested
// field name.
func (m FieldValueMap) GetSignedInt8(name string) (v int8, err error) {
	i, err := m.getValue(name, ValueTypeSignedInt8)
	if err == nil {
		v = i.(int8)
	}
	return
}

// GetSignedInt16 returns the signed 16-bit integer value set for the requested
// field name.
func (m FieldValueMap) GetSignedInt16(name string) (v int16, err error) {
	i, err := m.getValue(name, ValueTypeSignedInt16)
	if err == nil {
		v = i.(int16)
	}
	return
}

// GetSignedInt32 returns the signed 32-bit integer value set for the requested
// field name.
func (m FieldValueMap) GetSignedInt32(name string) (v int32, err error) {
	i, err := m.getValue(name, ValueTypeSignedInt32)
	if err == nil {
		v = i.(int32)
	}
	return
}

// GetSignedInt64 returns the signed 64-bit integer value set for the requested
// field name.
func (m FieldValueMap) GetSignedInt64(name string) (v int64, err error) {
	i, err := m.getValue(name, ValueTypeSignedInt64)
	if err == nil {
		v = i.(int64)
	}
	return
}

// GetUnsignedInt8 returns the unsigned 8-bit integer value set for the
// requested field name.
func (m FieldValueMap) GetUnsignedInt8(name string) (v uint8, err error) {
	i, err := m.getValue(name, ValueTypeUnsignedInt8)
	if err == nil {
		v = i.(uint8)
	}
	return
}

// GetUnsignedInt16 returns the unsigned 16-bit integer value set for the
// requested field name.
func (m FieldValueMap) GetUnsignedInt16(name string) (v uint16, err error) {
	i, err := m.getValue(name, ValueTypeUnsignedInt16)
	if err == nil {
		v = i.(uint16)
	}
	return
}

// GetUnsignedInt32 returns the unsigned 32-bit integer value set for the
// requested field name.
func (m FieldValueMap) GetUnsignedInt32(name string) (v uint32, err error) {
	i, err := m.getValue(name, ValueTypeUnsignedInt32)
	if err == nil {
		v = i.(uint32)
	}
	return
}

// GetUnsignedInt64 returns the unsigned 64-bit integer value set for the
// requested field name.
func (m FieldValueMap) GetUnsignedInt64(name string) (v uint64, err error) {
	i, err := m.getValue(name, ValueTypeUnsignedInt64)
	if err == nil {
		v = i.(uint64)
	}
	return
}

// GetBool returns the bool value set for the requested field name.
func (m FieldValueMap) GetBool(name string) (v bool, err error) {
	i, err := m.getValue(name, ValueTypeBool)
	if err == nil {
		v = i.(bool)
	}
	return
}

// GetDouble returns the double value set for the requested field name.
func (m FieldValueMap) GetDouble(name string) (v float64, err error) {
	i, err := m.getValue(name, ValueTypeDouble)
	if err == nil {
		v = i.(float64)
	}
	return
}

// GetTimestamp returns the timestamp value set for the requested field name.
func (m FieldValueMap) GetTimestamp(name string) (v time.Time, err error) {
	i, err := m.getValue(name, ValueTypeTimestamp)
	if err == nil {
		v = i.(time.Time)
	}
	return
}
