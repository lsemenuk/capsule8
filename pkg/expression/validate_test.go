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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type invalidExpr struct{}

func (e *invalidExpr) exprNode() {}
func (e *invalidExpr) String() string {
	return "<<invalidExpr String>>"
}
func (e *invalidExpr) KernelString() string {
	return "<<invalidExpr KernelString>>"
}
func (e *invalidExpr) BindTypes(types FieldTypeMap) error {
	return errors.New("cannot bind types")
}
func (e *invalidExpr) Type() ValueType {
	return ValueTypeUnspecified
}

func TestValidateIdentifier(t *testing.T) {
	badTests := []string{
		"", "CON$", "1234", "83foo",
	}
	goodTests := []string{
		"x", "abc83", "_", "_83_",
	}
	for _, tc := range badTests {
		err := validateIdentifier(tc)
		assert.Error(t, err, tc)
	}
	for _, tc := range goodTests {
		err := validateIdentifier(tc)
		assert.NoError(t, err, tc)
	}
}

func TestValidateKernelFilter(t *testing.T) {
	// identExpr tests
	ie := &identExpr{name: "foo"}
	err := validateKernelFilterTree(ie)
	assert.NoError(t, err)

	ie = &identExpr{name: "foo$"}
	err = validateKernelFilterTree(ie)
	assert.Error(t, err)

	// valueExpr tests
	valueTests := []struct {
		v           interface{}
		expectError bool
	}{
		{"string", false},
		{"string with a \" in it", true},
		{int8(8), false},
		{int16(8), false},
		{int32(8), false},
		{int64(8), false},
		{uint8(8), false},
		{uint16(8), false},
		{uint32(8), false},
		{uint64(8), false},
		{true, true},
		{8.0, true},
		{time.Now(), true},
	}
	for _, tc := range valueTests {
		ve := &valueExpr{v: tc.v}
		err = validateKernelFilterTree(ve)
		if tc.expectError {
			assert.Error(t, err, ve.String())
		} else {
			assert.NoError(t, err, ve.String())
		}
	}

	// binaryExpr tests
	logicalOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
	}
	for _, op := range logicalOps {
		be := &binaryExpr{op: op}
		err = validateKernelFilterTree(be)
		assert.Error(t, err, binaryOpStrings[op])

		be.x = &valueExpr{v: "string"}
		be.y = &valueExpr{v: "string"}
		err = validateKernelFilterTree(be)
		assert.NoError(t, err, binaryOpStrings[op])
	}

	binaryOps := []binaryOp{
		binaryOpEQ, binaryOpNE, binaryOpLT, binaryOpLE,
		binaryOpGT, binaryOpGE,
	}
	for _, op := range binaryOps {
		be := &binaryExpr{
			op: op,
			x:  &identExpr{name: "foo"},
			y:  &valueExpr{v: int32(8)},
		}
		err = validateKernelFilterTree(be)
		assert.NoError(t, err, binaryOpStrings[op])

		be.x = &valueExpr{v: int8(8)}
		err = validateKernelFilterTree(be)
		assert.Error(t, err)

		be.x = &identExpr{name: "foo"}
		be.y = &identExpr{name: "bar"}
		err = validateKernelFilterTree(be)
		assert.Error(t, err)
	}

	op := binaryOpLike
	be := &binaryExpr{
		op: op,
		x:  &identExpr{name: "foo"},
		y:  &valueExpr{v: "string"},
	}
	err = validateKernelFilterTree(be)
	assert.NoError(t, err)

	be.x = &valueExpr{v: int8(8)}
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be.x = &identExpr{name: "foo"}
	be.y = &identExpr{name: "bar"}
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be = &binaryExpr{
		op: binaryOpNE,
	}
	be.x = &binaryExpr{ // make an invalid bitwise-and
		op: binaryOpBitwiseAnd,
		x:  &identExpr{name: "foo"},
		y:  &valueExpr{v: "string"},
	}
	be.y = &identExpr{name: "invalid"}
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be.x = &binaryExpr{ // make a valid bitwise-and
		op: binaryOpBitwiseAnd,
		x:  &identExpr{name: "foo"},
		y:  &valueExpr{v: int32(8)},
	}
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be.y = &valueExpr{v: int8(8)} // invalid, signed
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be.y = &valueExpr{v: uint32(8)} // invalid, unsigned
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be.y = &valueExpr{v: "string"} // invalid, not integer
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be.y = &valueExpr{v: int64(0)} // VALID!
	err = validateKernelFilterTree(be)
	assert.NoError(t, err)

	be = &binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  &valueExpr{},
	}
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be = &binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  &identExpr{name: "foo"},
		y:  &identExpr{name: "bar"},
	}
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be = &binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  &identExpr{name: "foo"},
		y:  &valueExpr{v: "string"},
	}
	err = validateKernelFilterTree(be)
	assert.Error(t, err)

	be = &binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  &identExpr{name: "foo"},
		y:  &valueExpr{v: int8(8)},
	}
	err = validateKernelFilterTree(be)
	assert.NoError(t, err)

	// unaryExpr tests
	ue := &unaryExpr{
		op: unaryOpNot,
		x:  &identExpr{name: "foo"},
	}
	err = validateKernelFilterTree(ue)
	assert.NoError(t, err)

	// invalidExpr tests
	err = validateKernelFilterTree(&invalidExpr{})
	assert.Error(t, err)
}

func TestValidateTypes(t *testing.T) {
	e := &identExpr{name: "s", t: ValueTypeString}
	r, err := validateTypes(e)
	if assert.NoError(t, err) {
		assert.Equal(t, ValueTypeString, r)
	}

	// valueExpr tests
	ve := &valueExpr{v: "string"}
	vt, err := validateTypes(ve)
	if assert.NoError(t, err) {
		assert.Equal(t, ValueTypeString, vt)
	}

	ve.v = make(chan interface{})
	_, err = validateTypes(ve)
	assert.Error(t, err)

	// binaryExpr tests
	var be *binaryExpr

	logicalOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
	}
	for _, op := range logicalOps {
		testCase := binaryOpStrings[op]
		be = &binaryExpr{op: op}

		be.x = &valueExpr{v: make(chan interface{})}
		_, err = validateTypes(be)
		assert.Error(t, err, testCase)

		be.x = &identExpr{name: "s", t: ValueTypeString}
		_, err = validateTypes(be)
		assert.Error(t, err, testCase)

		be.x = &identExpr{name: "b", t: ValueTypeBool}
		be.y = &valueExpr{v: make(chan interface{})}
		_, err = validateTypes(be)
		assert.Error(t, err, testCase)

		be.y = &valueExpr{v: "string"}
		_, err = validateTypes(be)
		assert.Error(t, err, testCase)

		be.y = &valueExpr{true}
		_, err = validateTypes(be)
		assert.NoError(t, err, testCase)
	}

	binaryOps := []binaryOp{
		binaryOpEQ, binaryOpNE, binaryOpLT, binaryOpLE,
		binaryOpGT, binaryOpGE,
	}
	for _, op := range binaryOps {
		testCase := binaryOpStrings[op]
		be = &binaryExpr{op: op}

		be.x = &valueExpr{v: make(chan interface{})}
		_, err = validateTypes(be)
		assert.Error(t, err, testCase)

		be.x = &identExpr{name: "u16", t: ValueTypeUnsignedInt16}
		_, err = validateTypes(be)
		assert.Error(t, err, testCase)

		be.y = &identExpr{name: "s", t: ValueTypeString}
		_, err = validateTypes(be)
		assert.Error(t, err, testCase)

		be.y = &valueExpr{v: uint16(8)}
		_, err = validateTypes(be)
		assert.NoError(t, err, testCase)
	}

	binaryOps = []binaryOp{
		binaryOpLT, binaryOpLE, binaryOpGT, binaryOpGE,
	}
	for _, op := range binaryOps {
		be = &binaryExpr{
			op: op,
			x:  &identExpr{name: "s", t: ValueTypeString},
			y:  &valueExpr{v: int16(8)},
		}
		_, err = validateTypes(be)
		assert.Error(t, err, binaryOpStrings[op])
	}

	op := binaryOpLike
	be = &binaryExpr{op: op}

	be.x = &valueExpr{v: make(chan interface{})}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.x = &identExpr{name: "u16", t: ValueTypeUnsignedInt16}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.x = &identExpr{name: "s", t: ValueTypeString}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.y = &identExpr{name: "u16", t: ValueTypeUnsignedInt16}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.y = &valueExpr{v: "string"}
	_, err = validateTypes(be)
	assert.NoError(t, err)

	op = binaryOpBitwiseAnd
	be = &binaryExpr{op: op}
	be.x = &valueExpr{v: make(chan interface{})}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.x = &identExpr{name: "s", t: ValueTypeString}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.x = &identExpr{name: "u32", t: ValueTypeUnsignedInt32}
	be.y = &valueExpr{v: make(chan interface{})}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.y = &valueExpr{v: "string"}
	_, err = validateTypes(be)
	assert.Error(t, err)

	be.y = &valueExpr{v: uint32(8)}
	_, err = validateTypes(be)
	assert.NoError(t, err)

	be.op = 87364
	_, err = validateTypes(be)
	assert.Error(t, err)

	// unaryExpr tests
	ue := &unaryExpr{}

	ue.op = unaryOpIsNull
	ue.x = &identExpr{name: "s", t: ValueTypeString}
	vt, err = validateTypes(ue)
	if assert.NoError(t, err) {
		assert.Equal(t, ValueTypeBool, vt)
	}

	ue.op = unaryOpIsNotNull
	vt, err = validateTypes(ue)
	if assert.NoError(t, err) {
		assert.Equal(t, ValueTypeBool, vt)
	}

	ue.op = unaryOpNot
	_, err = validateTypes(ue)
	assert.Error(t, err)

	ue.x = &identExpr{name: "b", t: ValueTypeBool}
	vt, err = validateTypes(ue)
	if assert.NoError(t, err) {
		assert.Equal(t, ValueTypeBool, vt)
	}

	ue.op = 982375
	_, err = validateTypes(ue)
	assert.Error(t, err)

	// Test totally unsupported expr type
	_, err = validateTypes(&invalidExpr{})
	assert.Error(t, err)
}
