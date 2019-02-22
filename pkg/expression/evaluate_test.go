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

package expression

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type compareFunc func(lhs, rhs interface{}) bool

func compare(f compareFunc, lhs, rhs interface{}) (result bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	result = f(lhs, rhs)
	return
}

// This test tests all comparison functions except for compareLike
func TestSimpleComparisons(t *testing.T) {
	funcRefs := []compareFunc{
		compareEqual, compareNotEqual,
		compareLessThan, compareLessThanEqualTo,
		compareGreaterThan, compareGreaterThanEqualTo,
	}
	funcNames := []string{
		"compareEqual", "compareNotEqual",
		"compareLessThan", "compareLessThanEqualTo",
		"compareGreaterThan", "compareGreaterThanEqualTo",
	}

	invalidValue := make(chan interface{})

	lhs := []interface{}{
		"abc",
		int8(8), int16(8), int32(8), int64(8),
		uint8(8), uint16(8), uint32(8), uint64(8),
		true, 8.0, time.Unix(88888888, 88888888),
	}

	rhsTrue := [][]interface{}{
		// compareEqual
		lhs,
		// compareNotEqual
		[]interface{}{
			"xyz",
			int8(88), int16(88), int32(88), int64(88),
			uint8(88), uint16(88), uint32(88), uint64(88),
			false,
			88.0,
			time.Now(),
		},
		// compareLessThan
		[]interface{}{
			nil,
			int8(88), int16(88), int32(88), int64(88),
			uint(88), uint16(88), uint32(88), uint64(88),
			nil,
			88.0,
			time.Now(),
		},
		// compareLessThanEqualTo
		[]interface{}{
			nil,
			int8(8), int16(88), int32(8), int64(88),
			uint8(8), uint16(88), uint32(8), uint64(88),
			nil,
			8.0,
			time.Unix(88888888, 88888888),
		},
		// compareGreaterThan
		[]interface{}{
			nil,
			int8(0), int16(0), int32(0), int64(0),
			uint8(0), uint16(0), uint32(0), uint64(0),
			nil,
			0.0,
			time.Unix(0, 0),
		},
		// compareGreaterThanEqualTo
		[]interface{}{
			nil,
			int8(0), int16(8), int32(0), int64(8),
			uint8(0), uint16(8), uint32(0), uint64(8),
			nil,
			8.0,
			time.Unix(88888888, 88888888),
		},
	}
	rhsFalse := [][]interface{}{
		// compareEqual
		rhsTrue[1],
		// compareNotEqual
		rhsTrue[0],
		// compareLessThan
		rhsTrue[5],
		// compareLessThanEqualTo
		rhsTrue[4],
		// compareGreaterThan
		rhsTrue[3],
		// compareGreaterThanEqualTo
		rhsTrue[2],
	}

	for i, f := range funcRefs {
		name := funcNames[i]
		for j := range lhs {
			if v := rhsTrue[i][j]; reflect.ValueOf(v).Kind() != reflect.Invalid {
				testCase := fmt.Sprintf("%s(%v, %v)", name, lhs[j], v)
				r, err := compare(f, lhs[j], v)
				if assert.NoError(t, err, testCase) {
					assert.True(t, r, testCase)
				}
			} else {
				testCase := fmt.Sprintf("%s(%v, %v)", name, lhs[j], lhs[j])
				_, err := compare(f, lhs[j], lhs[j])
				assert.Error(t, err, testCase)
			}
			if v := rhsFalse[i][j]; reflect.ValueOf(v).Kind() != reflect.Invalid {
				testCase := fmt.Sprintf("%s(%v, %v)", name, lhs[j], v)
				r, err := compare(f, lhs[j], v)
				if assert.NoError(t, err, testCase) {
					assert.False(t, r, testCase)
				}
			} else {
				testCase := fmt.Sprintf("%s(%v, %v)", name, lhs[j], lhs[j])
				_, err := compare(f, lhs[j], lhs[j])
				assert.Error(t, err, testCase)
			}
		}
		_, err := compare(f, invalidValue, invalidValue)
		assert.Error(t, err, name)
	}
}

func TestCompareLike(t *testing.T) {
	// compareLike only works for strings. All other types should return
	// an error.

	lhs := "the quick brown fox jumped over the lazy dog"
	truePatterns := []string{
		"*lazy dog",
		"*brown fox*",
		"the quick brown fox*",
		"the quick brown fox jumped over the lazy dog",
	}
	falsePatterns := []string{
		"*the brown fox",
		"*aloof cat*",
		"the lazy dog*",
		"the lazy dog jumped over the quick brown fox",
	}

	for i := range truePatterns {
		tp := truePatterns[i]
		testCase := fmt.Sprintf("compareLike(%q, %q)", lhs, tp)
		r, err := compare(compareLike, lhs, tp)
		if assert.NoError(t, err, testCase) {
			assert.True(t, r, testCase)
		}
		fp := falsePatterns[i]
		testCase = fmt.Sprintf("compareLike(%q, %q)", lhs, fp)
		r, err = compare(compareLike, lhs, fp)
		if assert.NoError(t, err, testCase) {
			assert.False(t, r, testCase)
		}
	}

	invalidValues := []interface{}{
		int8(8), int16(8), int32(8), int64(8),
		uint8(8), uint16(8), uint32(8), uint64(8),
		true,
		8.0,
		time.Now(),
		make(chan interface{}),
	}
	for _, v := range invalidValues {
		_, err := compare(compareLike, v, v)
		assert.Error(t, err, reflect.TypeOf(v))
	}
}

func TestEvaluateExpression(t *testing.T) {
	types := FieldTypeMap{
		"s":   ValueTypeString,
		"i8":  ValueTypeSignedInt8,
		"i16": ValueTypeSignedInt16,
		"i32": ValueTypeSignedInt32,
		"i64": ValueTypeSignedInt64,
		"u8":  ValueTypeUnsignedInt8,
		"u16": ValueTypeUnsignedInt16,
		"u32": ValueTypeUnsignedInt32,
		"u64": ValueTypeUnsignedInt64,
		"b":   ValueTypeBool,
		"d":   ValueTypeDouble,
		"t":   ValueTypeTimestamp,

		"_d": ValueTypeDouble,    // value will be missing
		"_t": ValueTypeTimestamp, // value will be wrong type
	}
	values := FieldValueMap{
		"s":   "string",
		"i8":  int8(8),
		"i16": int16(8),
		"i32": int32(8),
		"i64": int64(8),
		"u8":  uint8(8),
		"u16": uint16(8),
		"u32": uint32(8),
		"u64": uint64(8),
		"b":   true,
		"d":   float64(8.0),
		"t":   time.Now(),

		//"_d":   8.0,         << this is intentionally omitted! >>
		"_t": "wrong type", // << this is intentionally the wrong type! >>
	}

	//
	// identExpr
	//

	ie := &identExpr{name: "_d", t: ValueTypeDouble}
	v, err := evaluateExpression(ie, types, values)
	if assert.NoError(t, err) {
		assert.Nil(t, v)
	}

	ie = &identExpr{name: "_t", t: ValueTypeTimestamp}
	_, err = evaluateExpression(ie, types, values)
	assert.Error(t, err)

	for k, v := range types {
		if k[0] == '_' {
			continue
		}
		ie = &identExpr{name: k, t: v}
		var i interface{}
		i, err = evaluateExpression(ie, types, values)
		if assert.NoError(t, err) {
			assert.Equal(t, values[k], i)
		}
	}

	//
	// valueExpr
	//

	ve := &valueExpr{v: int32(8)}
	v, err = evaluateExpression(ve, types, values)
	if assert.NoError(t, err) {
		assert.Equal(t, int32(8), v)
	}

	//
	// binaryExpr
	//

	logicalOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
	}
	for _, op := range logicalOps {
		be := &binaryExpr{
			x:  &valueExpr{v: "string"},
			op: op,
		}
		_, err = evaluateExpression(be, types, values)
		assert.Error(t, err, binaryOpStrings[op])
	}

	be := &binaryExpr{
		x:  &identExpr{name: "b", t: ValueTypeBool},
		y:  &valueExpr{v: false},
		op: binaryOpLogicalAnd,
	}
	r, err := evaluateExpression(be, types, values)
	if assert.NoError(t, err) && assert.IsType(t, true, r) {
		assert.False(t, r.(bool))
	}

	be = &binaryExpr{
		x:  &valueExpr{v: false},
		y:  &identExpr{name: "b", t: ValueTypeBool},
		op: binaryOpLogicalOr,
	}
	r, err = evaluateExpression(be, types, values)
	if assert.NoError(t, err) && assert.IsType(t, true, r) {
		assert.True(t, r.(bool))
	}

	binaryOps := map[binaryOp]bool{
		binaryOpEQ:   true,
		binaryOpNE:   false,
		binaryOpLT:   false,
		binaryOpLE:   true,
		binaryOpGT:   false,
		binaryOpGE:   true,
		binaryOpLike: false,
	}
	for op, expected := range binaryOps {
		opname := binaryOpStrings[op]
		be = &binaryExpr{
			x:  &identExpr{name: "_d", t: ValueTypeDouble},
			y:  &valueExpr{v: 8.0},
			op: op,
		}
		// This should be false because: d IS NULL
		r, err = evaluateExpression(be, types, values)
		if assert.NoError(t, err, opname) && assert.IsType(t, true, r, opname) {
			assert.False(t, r.(bool), opname)
		}

		// This should generate a type mismatch error
		be = &binaryExpr{
			x:  &identExpr{name: "u64", t: ValueTypeUnsignedInt64},
			y:  &valueExpr{v: "string"},
			op: op,
		}
		_, err = evaluateExpression(be, types, values)
		assert.Error(t, err, opname)

		if op == binaryOpLike {
			be = &binaryExpr{
				x:  &identExpr{name: "s", t: ValueTypeString},
				y:  &valueExpr{v: "foobarbaz"},
				op: op,
			}
		} else {
			be = &binaryExpr{
				x:  &identExpr{name: "i16", t: ValueTypeSignedInt16},
				y:  &valueExpr{v: int16(8)},
				op: op,
			}
		}
		r, err = evaluateExpression(be, types, values)
		if assert.NoError(t, err, opname) {
			assert.Equal(t, expected, r, opname)
		}
	}

	be = &binaryExpr{
		x:  &identExpr{name: "i8", t: ValueTypeSignedInt8},
		y:  &identExpr{name: "u8", t: ValueTypeUnsignedInt8},
		op: binaryOpBitwiseAnd,
	}
	// This should generate a type mismatch error
	_, err = evaluateExpression(be, types, values)
	assert.Error(t, err)

	be = &binaryExpr{
		x:  &identExpr{name: "s", t: ValueTypeString},
		y:  &valueExpr{v: "string"},
		op: binaryOpBitwiseAnd,
	}
	// This should generate an integer required error
	_, err = evaluateExpression(be, types, values)
	assert.Error(t, err)

	testCases := map[string]interface{}{
		"i8":  int8(8),
		"i16": int16(8),
		"i32": int32(8),
		"i64": int64(8),
		"u8":  uint8(8),
		"u16": uint16(8),
		"u32": uint32(8),
		"u64": uint64(8),
	}
	for name, value := range testCases {
		be = &binaryExpr{
			x:  &identExpr{name: name, t: ValueTypeOf(value)},
			y:  &valueExpr{v: value},
			op: binaryOpBitwiseAnd,
		}
		testCase := reflect.TypeOf(value)
		r, err = evaluateExpression(be, types, values)
		if assert.NoError(t, err, testCase) {
			assert.Equal(t, value, r, testCase)
		}
	}

	//
	// unaryExpr
	//

	ue := &unaryExpr{
		x:  &identExpr{name: "s", t: ValueTypeString},
		op: unaryOpIsNull,
	}
	r, err = evaluateExpression(ue, types, values)
	if assert.NoError(t, err) && assert.IsType(t, true, r) {
		assert.False(t, r.(bool))
	}
	ue.op = unaryOpIsNotNull
	r, err = evaluateExpression(ue, types, values)
	if assert.NoError(t, err) && assert.IsType(t, true, r) {
		assert.True(t, r.(bool))
	}

	ue = &unaryExpr{
		x:  &identExpr{name: "_d", t: ValueTypeDouble},
		op: unaryOpIsNull,
	}
	r, err = evaluateExpression(ue, types, values)
	if assert.NoError(t, err) && assert.IsType(t, true, r) {
		assert.True(t, r.(bool))
	}
	ue.op = unaryOpIsNotNull
	r, err = evaluateExpression(ue, types, values)
	if assert.NoError(t, err) && assert.IsType(t, true, r) {
		assert.False(t, r.(bool))
	}

	ue = &unaryExpr{
		op: unaryOpNot,
		x:  &identExpr{name: "b", t: ValueTypeBool},
	}
	r, err = evaluateExpression(ue, types, values)
	if assert.NoError(t, err) && assert.IsType(t, true, r) {
		assert.False(t, r.(bool))
	}
}

func TestEvaluateBadStackPanic(t *testing.T) {
	assert.Panics(t, func() {
		// This should leave the stack with three elements instead of just 1
		// since the initialization is creating a stack of len 2 initially.
		c := evalContext{
			stack: make([]interface{}, 2),
		}
		c.evaluateExpression(&valueExpr{v: "string"})
	})
}

func TestEvaluateNodePanic(t *testing.T) {
	assert.Panics(t, func() {
		c := evalContext{}
		c.evaluateNode(&invalidExpr{})
	})
}

func TestEvaluateBinaryExprPanic(t *testing.T) {
	assert.Panics(t, func() {
		c := evalContext{}
		c.evaluateBinaryExpr(&binaryExpr{op: 239487})
	})
}

func TestEvaluateUnaryExprPanic(t *testing.T) {
	assert.Panics(t, func() {
		c := evalContext{}
		c.evaluateUnaryExpr(&unaryExpr{op: 239487})
	})
}
