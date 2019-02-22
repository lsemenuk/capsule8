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
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

type parseError struct {
	error
	offset      int
	tokenOffset int
}

type parser struct {
	input scanner
	mode  ParseMode
	types FieldTypeMap

	// current token
	token       token
	tokenOffset int
	tokenText   string
}

func (p *parser) error(msg string) {
	panic(parseError{
		error:       errors.New(msg),
		offset:      p.tokenOffset,
		tokenOffset: p.tokenOffset,
	})
}

func (p *parser) errorf(msg string, args ...interface{}) {
	panic(parseError{
		error:       fmt.Errorf(msg, args...),
		offset:      p.tokenOffset,
		tokenOffset: p.tokenOffset,
	})
}

func (p *parser) next() {
	p.tokenOffset, p.token, p.tokenText = p.input.nextToken()
}

func (p *parser) makeNativeIntegerType(i interface{}, t ValueType) interface{} {
	var toType reflect.Type
	switch t {
	case ValueTypeSignedInt8:
		toType = reflect.TypeOf(int8(0))
	case ValueTypeSignedInt16:
		toType = reflect.TypeOf(int16(0))
	case ValueTypeSignedInt32:
		toType = reflect.TypeOf(int32(0))
	case ValueTypeSignedInt64:
		toType = reflect.TypeOf(int64(0))
	case ValueTypeUnsignedInt8:
		toType = reflect.TypeOf(uint8(0))
	case ValueTypeUnsignedInt16:
		toType = reflect.TypeOf(uint16(0))
	case ValueTypeUnsignedInt32:
		toType = reflect.TypeOf(uint32(0))
	case ValueTypeUnsignedInt64:
		toType = reflect.TypeOf(uint64(0))
	}
	return reflect.ValueOf(i).Convert(toType).Interface()
}

func (p *parser) fixupBinaryExpr(be *binaryExpr) expr {
	i, iok := be.x.(*identExpr)
	if !iok {
		p.errorf("lhs of %s must be an identifier",
			binaryOpStrings[be.op])
	}
	v, vok := be.y.(*valueExpr)
	if !vok {
		p.errorf("rhs of %s must be a literal value",
			binaryOpStrings[be.op])
	}
	if i.Type() == v.Type() {
		return be
	}
	if !i.Type().IsInteger() || !v.Type().IsInteger() {
		p.errorf("type mismatch (%s vs %s)",
			ValueTypeStrings[i.Type()],
			ValueTypeStrings[v.Type()])
	}

	v.v = p.makeNativeIntegerType(v.v, i.Type())

	return be
}

func (p *parser) parseOperand() expr {
	switch p.token {
	case tokenIdentifier:
		if t, ok := p.types[p.tokenText]; ok {
			e := &identExpr{name: p.tokenText, t: t}
			p.next()
			return e
		}
		p.errorf("unknown field: %q", p.tokenText)
	case tokenString:
		e := &valueExpr{v: p.tokenText}
		p.next()
		return e
	case tokenInteger:
		v, err := strconv.ParseUint(p.tokenText, 0, 64)
		if err != nil {
			// This is a sanity check. It should not actually be
			// reachable in production code. If it happens, it
			// points to a bug in scanner.scanNumber
			p.errorf("internal error parsing integer literal %q: %v",
				p.tokenText, err)
		}
		e := &valueExpr{v: v}
		p.next()
		return e

	case tokenLParen:
		p.next()
		e := p.parseLogicalOr()
		if e == nil {
			p.error("illegal operand")
		}
		if p.token != tokenRParen {
			p.error("expected closing paren")
		}
		p.next()
		return e

	case tokenMinus:
		p.next()
		op := p.parseOperand()
		switch e := op.(type) {
		case *valueExpr:
			switch v := e.v.(type) {
			case int64:
				e.v = uint64(-v)
			case uint64:
				e.v = -int64(v)
			default:
				p.error("illegal unary -")
			}
		default:
			p.error("illegal unary -")
		}
		return op

	case tokenNot:
		p.next()
		x := p.parseLogicalOr()
		if x.Type() != ValueTypeBool {
			p.errorf("operand to NOT must be type bool; got %s",
				ValueTypeStrings[x.Type()])
		}
		return &unaryExpr{
			op: unaryOpNot,
			x:  x,
		}

	case tokenEOF:
		return nil
	}
	p.errorf("unexpected token %q", p.tokenText)
	return nil // unreachable
}

func (p *parser) parseBitwiseAnd() expr {
	x := p.parseOperand()
	if x == nil {
		return nil
	}

	if p.token != tokenBitwiseAnd {
		return x
	}
	p.next()

	y := p.parseOperand()
	if y == nil {
		p.error("missing rhs for &")
	}

	e := &binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  x,
		y:  y,
	}
	if !e.x.Type().IsInteger() {
		p.errorf("illegal type for &: %s", ValueTypeStrings[e.x.Type()])
	}
	x = p.fixupBinaryExpr(e)

	x = &binaryExpr{
		op: binaryOpNE,
		x:  x,
		y:  &valueExpr{v: p.makeNativeIntegerType(0, x.Type())},
	}

	return x
}

func (p *parser) parseComparison() expr {
	x := p.parseBitwiseAnd()
	if x == nil {
		return nil
	}

	var op binaryOp
	switch p.token {
	case tokenLT:
		op = binaryOpLT
	case tokenLE:
		op = binaryOpLE
	case tokenGT:
		op = binaryOpGT
	case tokenGE:
		op = binaryOpGE
	default:
		return x
	}
	p.next()

	y := p.parseBitwiseAnd()
	if y == nil {
		p.errorf("missing rhs for %s", binaryOpStrings[op])
	}
	e := &binaryExpr{
		op: op,
		x:  x,
		y:  y,
	}
	x = p.fixupBinaryExpr(e)
	if !e.x.Type().IsNumeric() {
		p.errorf("operands for %s comparison must be numeric; got %s",
			binaryOpStrings[op], ValueTypeStrings[x.Type()])
	}

	return x
}

func (p *parser) parseEquality() expr {
	x := p.parseComparison()
	if x == nil {
		return nil
	}

	var op binaryOp
	switch p.token {
	case tokenEQ:
		op = binaryOpEQ
	case tokenNE:
		op = binaryOpNE
	case tokenLike:
		op = binaryOpLike
	default:
		return x
	}
	p.next()

	y := p.parseComparison()
	if y == nil {
		p.errorf("missing rhs for %s", binaryOpStrings[op])
	}
	e := &binaryExpr{
		op: op,
		x:  x,
		y:  y,
	}
	x = p.fixupBinaryExpr(e)

	if op == binaryOpLike && e.x.Type() != ValueTypeString {
		p.errorf("operands for ~ must be string; got %s",
			ValueTypeStrings[e.x.Type()])
	}

	return x
}

func (p *parser) parseLogicalAnd() expr {
	x := p.parseEquality()
	if x == nil {
		return nil
	}

	for {
		if p.token != tokenLogicalAnd {
			return x
		}
		p.next()

		y := p.parseEquality()
		if y == nil {
			p.error("missing rhs for logical and")
		}
		if x.Type() != ValueTypeBool {
			p.errorf("lhs for logical and must be bool; got %s",
				ValueTypeStrings[x.Type()])
		}
		if y.Type() != ValueTypeBool {
			p.errorf("rhs for logical and must be bool; got %s",
				ValueTypeStrings[y.Type()])
		}

		x = &binaryExpr{
			op: binaryOpLogicalAnd,
			x:  x,
			y:  y,
		}
	}
}

func (p *parser) parseLogicalOr() expr {
	x := p.parseLogicalAnd()
	if x == nil {
		return nil
	}

	for {
		if p.token != tokenLogicalOr {
			return x
		}
		p.next()

		y := p.parseLogicalAnd()
		if y == nil {
			p.error("missing rhs for logical or")
		}
		if x.Type() != ValueTypeBool {
			p.errorf("lhs for logical or must be bool; got %s",
				ValueTypeStrings[x.Type()])
		}
		if y.Type() != ValueTypeBool {
			p.errorf("rhs for logical or must be bool; got %s",
				ValueTypeStrings[y.Type()])
		}
		x = &binaryExpr{
			op: binaryOpLogicalOr,
			x:  x,
			y:  y,
		}
	}
}

func (p *parser) parse() (e *Expression, err error) {
	defer func() {
		if r := recover(); r != nil {
			if pe, ok := r.(parseError); ok {
				err = pe.error
			} else {
				panic(r)
			}
		}
	}()

	p.next()
	ast := p.parseLogicalOr()
	if p.token != tokenEOF {
		p.errorf("unexpected token %q", p.tokenText)
	}
	if ast == nil {
		ast = &valueExpr{v: true}
	}
	e = &Expression{
		ast:   ast,
		types: p.types,
	}
	return
}
