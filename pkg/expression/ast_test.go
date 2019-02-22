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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIdentExpr(t *testing.T) {
	e := identExpr{name: "foo", t: ValueTypeString}
	assert.Equal(t, "foo", e.String())
	assert.Equal(t, "foo", e.KernelString())
	assert.Equal(t, ValueTypeString, e.Type())

	types := FieldTypeMap{
		"s": ValueTypeString,
	}
	e = identExpr{name: "s"}
	err := e.BindTypes(types)
	if assert.NoError(t, err) {
		assert.Equal(t, ValueTypeString, e.t)
	}

	e = identExpr{name: "foo"}
	err = e.BindTypes(types)
	assert.Error(t, err)
}

func TestValueExprString(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		v      interface{}
		expect string
		kernel string
	}{
		{"string with a \" in it", "\"string with a \\\" in it\"", "\"string with a \" in it\""},
		{int8(8), "8", "8"},
		{int16(8), "8", "8"},
		{int32(8), "8", "8"},
		{int64(8), "8", "8"},
		{uint8(8), "8", "8"},
		{uint16(8), "8", "8"},
		{uint32(8), "8", "8"},
		{uint64(8), "8", "8"},
		{true, "TRUE", ""},
		{false, "FALSE", ""},
		{8.0, fmt.Sprintf("%f", 8.0), ""},
		{now, fmt.Sprintf("TIMESTAMP(%d)", now.UnixNano()), ""},
	}

	for _, tc := range testCases {
		v := valueExpr{v: tc.v}
		assert.Equal(t, tc.expect, v.String())
		assert.Equal(t, tc.kernel, v.KernelString())
	}

	assert.Panics(t, func() {
		_ = (&valueExpr{v: make(chan interface{})}).String()
	})
}

func TestValueExprBindTypes(t *testing.T) {
	types := FieldTypeMap{
		"s": ValueTypeString,
	}
	e := valueExpr{v: "string"}
	err := e.BindTypes(types)
	assert.NoError(t, err)
}

func TestValueExprType(t *testing.T) {
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
		e := valueExpr{v: tc.v}
		assert.Equalf(t, tc.t, e.Type(), "%#v", tc.v)
	}
}

func TestValueExprIsInteger(t *testing.T) {
	goodTests := []interface{}{
		int8(8),
		int16(8),
		int32(8),
		int64(8),
		uint8(8),
		uint16(8),
		uint32(8),
		uint64(8),
	}
	for _, tc := range goodTests {
		v := valueExpr{v: tc}
		assert.Truef(t, v.isInteger(),
			"test case: %#v", tc)
	}

	badTests := []interface{}{
		make(chan interface{}),
		"string",
		true,
		8.0,
		time.Now(),
	}
	for _, tc := range badTests {
		v := valueExpr{v: tc}
		assert.Falsef(t, v.isInteger(),
			"test case: %#v", tc)
	}
}

func TestValueExprIsNumeric(t *testing.T) {
	goodTests := []interface{}{
		int8(8),
		int16(8),
		int32(8),
		int64(8),
		uint8(8),
		uint16(8),
		uint32(8),
		uint64(8),
		8.0,
		time.Now(),
	}
	for _, tc := range goodTests {
		v := valueExpr{v: tc}
		assert.Truef(t, v.isNumeric(),
			"test case: %#v", tc)
	}

	badTests := []interface{}{
		make(chan interface{}),
		"string",
		true,
	}
	for _, tc := range badTests {
		v := valueExpr{v: tc}
		assert.Falsef(t, v.isNumeric(),
			"test case: %#v", tc)
	}
}

func TestValueExprIsString(t *testing.T) {
	goodTests := []interface{}{
		"string",
	}
	for _, tc := range goodTests {
		v := valueExpr{v: tc}
		assert.Truef(t, v.isString(),
			"test case: %#v", tc)
	}

	badTests := []interface{}{
		make(chan interface{}),
		int8(8),
		int16(8),
		int32(8),
		int64(8),
		uint8(8),
		uint16(8),
		uint32(8),
		uint64(8),
		true,
		8.0,
		time.Now(),
	}
	for _, tc := range badTests {
		v := valueExpr{v: tc}
		assert.Falsef(t, v.isString(),
			"test case: %#v", tc)
	}
}

func TestBinaryExprIsValid(t *testing.T) {
	binaryOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
		binaryOpEQ, binaryOpNE, binaryOpLT, binaryOpLE,
		binaryOpGT, binaryOpGE, binaryOpLike,
		binaryOpBitwiseAnd,
	}

	for _, op := range binaryOps {
		be := binaryExpr{op: op}
		assert.Truef(t, be.isValid(),
			"test case: %s", binaryOpStrings[op])
	}

	be := binaryExpr{op: 29384675}
	assert.False(t, be.isValid())
}

func TestBinaryExprString(t *testing.T) {
	be := &binaryExpr{
		x: &identExpr{name: "foo"},
		y: &valueExpr{v: int32(8)},
	}
	binaryOps := map[binaryOp][]string{
		binaryOpEQ: []string{"foo = 8", "foo == 8"},
		binaryOpNE: []string{"foo != 8", "foo != 8"},
		binaryOpLT: []string{"foo < 8", "foo < 8"},
		binaryOpLE: []string{"foo <= 8", "foo <= 8"},
		binaryOpGT: []string{"foo > 8", "foo > 8"},
		binaryOpGE: []string{"foo >= 8", "foo >= 8"},
	}
	for op, expectations := range binaryOps {
		be.op = op
		assert.Equal(t, expectations[0], be.String())
		assert.Equal(t, expectations[1], be.KernelString())
	}

	be.op = binaryOpLike
	be.y = &valueExpr{v: "string"}
	assert.Equal(t, "foo LIKE \"string\"", be.String())
	assert.Equal(t, "foo ~ \"string\"", be.KernelString())

	logicalOps := map[binaryOp][]string{
		binaryOpLogicalAnd: []string{
			"foo = 8 AND bar = 8", "foo == 8 && bar == 8",
			"foo = 8 AND bar = 8 AND baz = 8", "foo == 8 && bar == 8 && baz == 8",
			"foo = 8 AND (bar = 8 AND baz = 8)", "foo == 8 && (bar == 8 && baz == 8)",
		},
		binaryOpLogicalOr: []string{
			"foo = 8 OR bar = 8", "foo == 8 || bar == 8",
			"foo = 8 OR bar = 8 OR baz = 8", "foo == 8 || bar == 8 || baz == 8",
			"foo = 8 OR (bar = 8 OR baz = 8)", "foo == 8 || (bar == 8 || baz == 8)",
		},
	}
	logical1 := &binaryExpr{
		op: binaryOpEQ,
		x:  &identExpr{name: "foo"},
		y:  &valueExpr{v: int32(8)},
	}
	logical2 := &binaryExpr{
		op: binaryOpEQ,
		x:  &identExpr{name: "bar"},
		y:  &valueExpr{v: int64(8)},
	}
	logical3 := &binaryExpr{
		op: binaryOpEQ,
		x:  &identExpr{name: "baz"},
		y:  &valueExpr{v: uint32(8)},
	}
	for op, expectations := range logicalOps {
		be = &binaryExpr{
			op: op,
			x:  logical1,
			y:  logical2,
		}
		assert.Equal(t, expectations[0], be.String())
		assert.Equal(t, expectations[1], be.KernelString())

		be = &binaryExpr{
			op: op,
			x: &binaryExpr{
				op: op,
				x:  logical1,
				y:  logical2,
			},
			y: logical3,
		}
		assert.Equal(t, expectations[2], be.String())
		assert.Equal(t, expectations[3], be.KernelString())

		be = &binaryExpr{
			op: op,
			x:  logical1,
			y: &binaryExpr{
				op: op,
				x:  logical2,
				y:  logical3,
			},
		}
		assert.Equal(t, expectations[4], be.String())
		assert.Equal(t, expectations[5], be.KernelString())
	}

	be = &binaryExpr{
		op: binaryOpNE,
		x: &binaryExpr{
			op: binaryOpBitwiseAnd,
			x:  &identExpr{name: "foo"},
			y:  &valueExpr{v: uint32(0x8888)},
		},
		y: &valueExpr{v: uint32(0)},
	}
	assert.Equal(t, "foo & 34952 != 0", be.String())
	assert.Equal(t, "foo & 34952", be.KernelString())

	assert.Panics(t, func() {
		_ = (&binaryExpr{op: 397485}).String()
	})

	assert.Panics(t, func() {
		_ = (&binaryExpr{op: 9238745}).KernelString()
	})
}

func TestBinaryExprBindTypes(t *testing.T) {
	types := FieldTypeMap{
		"u16": ValueTypeUnsignedInt16,
	}
	b := &binaryExpr{
		op: binaryOpEQ,
		x:  &identExpr{name: "u16"},
		y:  &valueExpr{v: uint16(8)},
	}
	err := b.BindTypes(types)
	assert.NoError(t, err)

	b.x = &identExpr{name: "foo"}
	err = b.BindTypes(types)
	assert.Error(t, err)
}

func TestBinaryExprType(t *testing.T) {
	i := &identExpr{name: "u16", t: ValueTypeUnsignedInt16}
	v := &valueExpr{v: uint16(8)}
	testCases := []struct {
		op     binaryOp
		expect ValueType
	}{
		{binaryOpLogicalAnd, ValueTypeBool},
		{binaryOpLogicalOr, ValueTypeBool},
		{binaryOpEQ, ValueTypeBool},
		{binaryOpNE, ValueTypeBool},
		{binaryOpLT, ValueTypeBool},
		{binaryOpLE, ValueTypeBool},
		{binaryOpGT, ValueTypeBool},
		{binaryOpGE, ValueTypeBool},
		{binaryOpLike, ValueTypeBool},
		{binaryOpBitwiseAnd, ValueTypeUnsignedInt16},
	}
	for _, tc := range testCases {
		e := &binaryExpr{
			op: tc.op,
			x:  i,
			y:  v,
		}
		assert.Equal(t, tc.expect, e.Type())
	}

	assert.Panics(t, func() {
		_ = (&binaryExpr{op: 293847}).Type()
	})
}

func TestUnaryExprString(t *testing.T) {
	unaryOps := map[unaryOp][2]string{
		unaryOpIsNull:    {"foo IS NULL", ""},
		unaryOpIsNotNull: {"foo IS NOT NULL", ""},
		unaryOpNot:       {"NOT foo", "!foo"},
	}
	for op, want := range unaryOps {
		ue := &unaryExpr{
			op: op,
			x:  &identExpr{name: "foo"},
		}
		assert.Equal(t, want[0], ue.String())
		assert.Equal(t, want[1], ue.KernelString())
	}

	assert.Panics(t, func() {
		_ = (&unaryExpr{op: 234987}).String()
	})
}

func TestUnaryExprBindTypes(t *testing.T) {
	ops := []unaryOp{
		unaryOpIsNull,
		unaryOpIsNotNull,
		unaryOpNot,
	}

	types := FieldTypeMap{
		"u16": ValueTypeUnsignedInt16,
	}

	for _, op := range ops {
		u := &unaryExpr{
			op: op,
			x:  &identExpr{name: "u16"},
		}
		err := u.BindTypes(types)
		assert.NoError(t, err, unaryOpStrings[op])

		u.x = &identExpr{name: "foo"}
		err = u.BindTypes(types)
		assert.Error(t, err, unaryOpStrings[op])
	}
}

func TestUnaryExprType(t *testing.T) {
	testCases := []struct {
		op          unaryOp
		operandName string
		operandType ValueType
		expect      ValueType
	}{
		{unaryOpIsNull, "u16", ValueTypeUnsignedInt16, ValueTypeBool},
		{unaryOpIsNotNull, "u16", ValueTypeUnsignedInt16, ValueTypeBool},
		{unaryOpNot, "b", ValueTypeBool, ValueTypeBool},
	}
	for _, tc := range testCases {
		i := &identExpr{name: tc.operandName, t: tc.operandType}
		e := &unaryExpr{
			op: tc.op,
			x:  i,
		}
		assert.Equal(t, tc.expect, e.Type())
	}

	assert.Panics(t, func() {
		_ = (&unaryExpr{op: 293847}).Type()
	})
}
