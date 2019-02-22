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

	"github.com/stretchr/testify/assert"
)

var parserTestTypes = FieldTypeMap{
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
}

func (p *parser) errorWrapper(msg string) (r interface{}) {
	defer func() {
		r = recover()
	}()
	p.error(msg)
	return
}

func TestParserError(t *testing.T) {
	p := parser{
		tokenOffset: 2908374,
	}
	i := p.errorWrapper("error message")
	if assert.IsType(t, parseError{}, i) {
		e := i.(parseError)
		assert.Equal(t, p.tokenOffset, e.offset)
		assert.Equal(t, p.tokenOffset, e.tokenOffset)
	}
}

func (p *parser) errorfWrapper(msg string, args ...interface{}) (r interface{}) {
	defer func() {
		r = recover()
	}()
	p.errorf(msg, args...)
	return
}

func TestParserErrorf(t *testing.T) {
	p := parser{
		tokenOffset: 2908374,
	}
	i := p.errorfWrapper("error %s", "message")
	if assert.IsType(t, parseError{}, i) {
		e := i.(parseError)
		assert.Equal(t, p.tokenOffset, e.offset)
		assert.Equal(t, p.tokenOffset, e.tokenOffset)
	}
}

func TestParserNext(t *testing.T) {
	p := parser{
		input: scanner{
			input: []byte("foo != 2"),
		},
	}

	p.next()
	assert.Equal(t, 0, p.tokenOffset)
	assert.Equal(t, tokenIdentifier, p.token)
	assert.Equal(t, "foo", p.tokenText)

	p.next()
	assert.Equal(t, 4, p.tokenOffset)
	assert.Equal(t, tokenNE, p.token)
	assert.Equal(t, "!=", p.tokenText)

	p.next()
	assert.Equal(t, 7, p.tokenOffset)
	assert.Equal(t, tokenInteger, p.token)
	assert.Equal(t, "2", p.tokenText)

	p.next()
	assert.Equal(t, 8, p.tokenOffset)
	assert.Equal(t, tokenEOF, p.token)
	assert.Equal(t, "", p.tokenText)
}

func TestMakeNativeIntegerType(t *testing.T) {
	valuesByType := map[ValueType]interface{}{
		ValueTypeSignedInt8:    int8(8),
		ValueTypeSignedInt16:   int16(8),
		ValueTypeSignedInt32:   int32(8),
		ValueTypeSignedInt64:   int64(8),
		ValueTypeUnsignedInt8:  uint8(8),
		ValueTypeUnsignedInt16: uint16(8),
		ValueTypeUnsignedInt32: uint32(8),
		ValueTypeUnsignedInt64: uint64(8),
	}

	p := parser{}
	for vt, expect := range valuesByType {
		got := p.makeNativeIntegerType(8, vt)
		assert.Equal(t, expect, got, ValueTypeStrings[vt])
	}
}

func TestParserFixupBinaryExpr(t *testing.T) {
	p := parser{}

	// lhs must be an identifier
	assert.Panics(t, func() {
		be := &binaryExpr{
			op: binaryOpEQ,
			x:  &valueExpr{v: "string"},
			y:  &identExpr{name: "s", t: ValueTypeString},
		}
		p.fixupBinaryExpr(be)
	})

	// rhs must be a value
	assert.Panics(t, func() {
		be := &binaryExpr{
			op: binaryOpEQ,
			x:  &identExpr{name: "s", t: ValueTypeString},
			y:  &identExpr{name: "foo", t: ValueTypeString},
		}
		p.fixupBinaryExpr(be)
	})

	valueTypes := []ValueType{
		ValueTypeString,
		ValueTypeSignedInt8,
		ValueTypeSignedInt16,
		ValueTypeSignedInt32,
		ValueTypeSignedInt64,
		ValueTypeUnsignedInt8,
		ValueTypeUnsignedInt16,
		ValueTypeUnsignedInt32,
		ValueTypeUnsignedInt64,
	}
	valuesByType := map[ValueType]interface{}{
		ValueTypeString:        "string",
		ValueTypeSignedInt8:    int8(8),
		ValueTypeSignedInt16:   int16(8),
		ValueTypeSignedInt32:   int32(8),
		ValueTypeSignedInt64:   int64(8),
		ValueTypeUnsignedInt8:  uint8(8),
		ValueTypeUnsignedInt16: uint16(8),
		ValueTypeUnsignedInt32: uint32(8),
		ValueTypeUnsignedInt64: uint64(8),
	}
	for _, lhsType := range valueTypes {
		for _, rhsType := range valueTypes {
			be := &binaryExpr{
				op: binaryOpEQ,
				x:  &identExpr{name: "foo", t: lhsType},
				y:  &valueExpr{v: valuesByType[rhsType]},
			}
			if lhsType != rhsType && (!lhsType.IsInteger() || !rhsType.IsInteger()) {
				assert.Panicsf(t, func() {
					p.fixupBinaryExpr(be)
				},
					"%s vs. %s",
					ValueTypeStrings[lhsType],
					ValueTypeStrings[rhsType])
			} else {
				p.fixupBinaryExpr(be)
				assert.Equalf(t,
					valuesByType[lhsType], be.y.(*valueExpr).v,
					"%s vs. %s",
					ValueTypeStrings[lhsType],
					ValueTypeStrings[rhsType])
			}
		}
	}
}

func TestParserParseOperand(t *testing.T) {
	goodTestCases := []struct {
		input  string
		expect expr
	}{
		{"s == 452", &identExpr{name: "s", t: ValueTypeString}},
		{"\"string\"", &valueExpr{v: "string"}},
		{"12345678", &valueExpr{v: uint64(12345678)}},
		{"(123)", &valueExpr{v: uint64(123)}},
		{"-123", &valueExpr{v: int64(-123)}},
		{"--123", &valueExpr{v: uint64(123)}},
		{"---123", &valueExpr{v: int64(-123)}},
		{"!b", &unaryExpr{op: unaryOpNot, x: &identExpr{name: "b", t: ValueTypeBool}}},
		{"", nil},
	}
	for i, tc := range goodTestCases {
		p := parser{
			input: scanner{input: []byte(tc.input)},
			types: parserTestTypes,
		}
		p.next()
		got := p.parseOperand()
		assert.Equalf(t, tc.expect, got, "index %d (%s)", i, tc.input)
	}

	badTestCases := []string{
		"foo != 12", // unknown field: "foo"
		"(",         // illegal operand
		"(123",      // expected closing paren
		"-u16",      // illegal unary -
		"-\"abc\"",  // illegal unary -
		"!s",        // operand to NOT must be type bool; got string
		"&&",        // unexpected token "&&"
	}
	for i, tc := range badTestCases {
		assert.Panicsf(t, func() {
			p := parser{
				input: scanner{input: []byte(tc)},
				types: parserTestTypes,
			}
			p.next()
			p.parseOperand()
		}, "index %d (%s)", i, tc)
	}
}

func TestParserParseBitwiseAnd(t *testing.T) {
	goodTestCases := []struct {
		input        string
		expect       string
		expectedType interface{}
	}{
		{"", "", nil},
		{"s", "s", &identExpr{}},
		{"u16 & 0x80", "u16 & 128", &binaryExpr{}},
	}
	for i, tc := range goodTestCases {
		p := parser{
			input: scanner{input: []byte(tc.input)},
			types: parserTestTypes,
		}
		p.next()
		ast := p.parseBitwiseAnd()
		var got string
		if ast != nil {
			got = ast.KernelString()
		}
		assert.Equalf(t, tc.expect, got, "index %d (%s)", i, tc.input)
		assert.IsTypef(t, tc.expectedType, ast, "index %d (%s)", i, tc.input)
		if e, ok := ast.(*binaryExpr); ok {
			assert.Equalf(t, e.x.Type(), e.y.Type(), "index %d (%s)", i, tc.input)
		}
	}

	badTestCases := []string{
		"u32 &",
		"s & \"foo\"",
	}
	for i, tc := range badTestCases {
		assert.Panicsf(t, func() {
			p := parser{
				input: scanner{input: []byte(tc)},
				types: parserTestTypes,
			}
			p.next()
			p.parseBitwiseAnd()
		}, "index %d (%s)", i, tc)
	}

}

func TestParserParseComparison(t *testing.T) {
	goodTestCases := []struct {
		input  string
		expect string
	}{
		{"", ""},
		{"s", "s"},
		{"u16 >= 0x80", "u16 >= 128"},
		{"u8 <= 12", "u8 <= 12"},
		{"i64 > -123", "i64 > -123"},
		{"i32 < -0x80", "i32 < -128"},
	}
	for i, tc := range goodTestCases {
		p := parser{
			input: scanner{input: []byte(tc.input)},
			types: parserTestTypes,
		}
		p.next()
		ast := p.parseComparison()
		var got string
		if ast != nil {
			got = ast.KernelString()
		}
		assert.Equalf(t, tc.expect, got, "index %d (%s)", i, tc.input)
	}

	badTestCases := []string{
		"u32 >=",
		"u16 <",
		"i64 <=",
		"i8 >",
		"s > \"abc\"",
	}
	for i, tc := range badTestCases {
		assert.Panicsf(t, func() {
			p := parser{
				input: scanner{input: []byte(tc)},
				types: parserTestTypes,
			}
			p.next()
			p.parseComparison()
		}, "index %d (%s)", i, tc)
	}
}

func TestParserParseEquality(t *testing.T) {
	goodTestCases := []struct {
		input  string
		expect string
	}{
		{"", ""},
		{"s", "s"},
		{"u16 == 0x80", "u16 == 128"},
		{"u8 != 12", "u8 != 12"},
		{"s ~ \"*abc*\"", "s ~ \"*abc*\""},
	}
	for i, tc := range goodTestCases {
		p := parser{
			input: scanner{input: []byte(tc.input)},
			types: parserTestTypes,
		}
		p.next()
		ast := p.parseEquality()
		var got string
		if ast != nil {
			got = ast.KernelString()
		}
		assert.Equalf(t, tc.expect, got, "index %d (%s)", i, tc.input)
	}

	badTestCases := []string{
		"s ==",
		"s != ",
		"u16 ~ 128",
	}
	for i, tc := range badTestCases {
		assert.Panicsf(t, func() {
			p := parser{
				input: scanner{input: []byte(tc)},
				types: parserTestTypes,
			}
			p.next()
			p.parseEquality()
		}, "index %d (%s)", i, tc)
	}
}

func TestParserParseLogicalAnd(t *testing.T) {
	goodTestCases := []struct {
		input  string
		expect string
	}{
		{"", ""},
		{"s", "s"},
		{"u16 == 0x80 && u8 != 12", "u16 == 128 && u8 != 12"},
	}
	for i, tc := range goodTestCases {
		p := parser{
			input: scanner{input: []byte(tc.input)},
			types: parserTestTypes,
		}
		p.next()
		ast := p.parseLogicalAnd()
		var got string
		if ast != nil {
			got = ast.KernelString()
		}
		assert.Equalf(t, tc.expect, got, "index %d (%s)", i, tc.input)
	}

	badTestCases := []string{
		"u16 == 12 &&",
		"s && u16 == 12",
		"u16==12&&s",
	}
	for i, tc := range badTestCases {
		assert.Panicsf(t, func() {
			p := parser{
				input: scanner{input: []byte(tc)},
				types: parserTestTypes,
			}
			p.next()
			p.parseLogicalAnd()
		}, "index %d (%s)", i, tc)
	}
}

func TestParserParseLogicalOr(t *testing.T) {
	goodTestCases := []struct {
		input  string
		expect string
	}{
		{"", ""},
		{"s", "s"},
		{"u16 == 0x80 || u8 != 12", "u16 == 128 || u8 != 12"},
	}
	for i, tc := range goodTestCases {
		p := parser{
			input: scanner{input: []byte(tc.input)},
			types: parserTestTypes,
		}
		p.next()
		ast := p.parseLogicalOr()
		var got string
		if ast != nil {
			got = ast.KernelString()
		}
		assert.Equalf(t, tc.expect, got, "index %d (%s)", i, tc.input)
	}

	badTestCases := []string{
		"i64 != 8 ||",
		"s || u16 == 12",
		"u16==12||s",
	}
	for i, tc := range badTestCases {
		assert.Panicsf(t, func() {
			p := parser{
				input: scanner{input: []byte(tc)},
				types: parserTestTypes,
			}
			p.next()
			p.parseLogicalOr()
		}, "index %d (%s)", i, tc)
	}
}

func TestParserParse(t *testing.T) {
	goodTestCases := []struct {
		input  string
		expect string
	}{
		{"u16 == 12 || (u64 == 13 || i64 <= 9)", "u16 == 12 || (u64 == 13 || i64 <= 9)"},
		{"", ""},
	}
	for i, tc := range goodTestCases {
		p := parser{
			input: scanner{input: []byte(tc.input)},
			types: parserTestTypes,
		}
		e, err := p.parse()
		assert.NoErrorf(t, err, "index %d (%s)", i, tc.input)
		assert.NotNilf(t, e, "index %d (%s)", i, tc.input)

		got := e.KernelFilterString()
		assert.Equalf(t, tc.expect, got, "index %d (%s)", i, tc.input)
	}

	badTestCases := []string{
		"u16 == 12 == 4",
		"u8 & 4 & 9",
	}
	for i, tc := range badTestCases {
		p := parser{
			input: scanner{input: []byte(tc)},
			types: parserTestTypes,
		}
		_, err := p.parse()
		assert.Errorf(t, err, "index %d (%s)", i, tc)
	}
}
