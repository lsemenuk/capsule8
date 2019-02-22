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
	"strings"
	"time"
)

// For all comparisons, we know that the types of lhs and rhs are identical,
// because they've been checked already in evaluateBinaryExpr.

func compareEqual(lhs, rhs interface{}) (r bool) {
	switch lhs.(type) {
	case string:
		r = reflect.ValueOf(lhs).String() == reflect.ValueOf(rhs).String()
	case int8, int16, int32, int64:
		r = reflect.ValueOf(lhs).Int() == reflect.ValueOf(rhs).Int()
	case uint8, uint16, uint32, uint64:
		r = reflect.ValueOf(lhs).Uint() == reflect.ValueOf(rhs).Uint()
	case bool:
		r = reflect.ValueOf(lhs).Bool() == reflect.ValueOf(rhs).Bool()
	case float64:
		r = reflect.ValueOf(lhs).Float() == reflect.ValueOf(rhs).Float()
	case time.Time:
		r = lhs.(time.Time).UnixNano() == rhs.(time.Time).UnixNano()
	default:
		exprRaise(fmt.Errorf("Unknown value type %s", reflect.TypeOf(lhs)))
	}
	return
}

func compareNotEqual(lhs, rhs interface{}) (r bool) {
	switch lhs.(type) {
	case string:
		r = reflect.ValueOf(lhs).String() != reflect.ValueOf(rhs).String()
	case int8, int16, int32, int64:
		r = reflect.ValueOf(lhs).Int() != reflect.ValueOf(rhs).Int()
	case uint8, uint16, uint32, uint64:
		r = reflect.ValueOf(lhs).Uint() != reflect.ValueOf(rhs).Uint()
	case bool:
		r = reflect.ValueOf(lhs).Bool() != reflect.ValueOf(rhs).Bool()
	case float64:
		r = reflect.ValueOf(lhs).Float() != reflect.ValueOf(rhs).Float()
	case time.Time:
		r = lhs.(time.Time).UnixNano() != rhs.(time.Time).UnixNano()
	default:
		exprRaise(fmt.Errorf("Unknown value type %s", reflect.TypeOf(lhs)))
	}
	return
}

func compareLessThan(lhs, rhs interface{}) (r bool) {
	switch lhs.(type) {
	case string, bool:
		exprRaise(fmt.Errorf("Cannot compare %s types", reflect.TypeOf(lhs)))
	case int8, int16, int32, int64:
		r = reflect.ValueOf(lhs).Int() < reflect.ValueOf(rhs).Int()
	case uint8, uint16, uint32, uint64:
		r = reflect.ValueOf(lhs).Uint() < reflect.ValueOf(rhs).Uint()
	case float64:
		r = reflect.ValueOf(lhs).Float() < reflect.ValueOf(rhs).Float()
	case time.Time:
		r = lhs.(time.Time).UnixNano() < rhs.(time.Time).UnixNano()
	default:
		exprRaise(fmt.Errorf("Unknown value type %s", reflect.TypeOf(lhs)))
	}
	return
}

func compareLessThanEqualTo(lhs, rhs interface{}) (r bool) {
	switch lhs.(type) {
	case string, bool:
		exprRaise(fmt.Errorf("Cannot compare %s types", reflect.TypeOf(lhs)))
	case int8, int16, int32, int64:
		r = reflect.ValueOf(lhs).Int() <= reflect.ValueOf(rhs).Int()
	case uint8, uint16, uint32, uint64:
		r = reflect.ValueOf(lhs).Uint() <= reflect.ValueOf(rhs).Uint()
	case float64:
		r = reflect.ValueOf(lhs).Float() <= reflect.ValueOf(rhs).Float()
	case time.Time:
		r = lhs.(time.Time).UnixNano() <= rhs.(time.Time).UnixNano()
	default:
		exprRaise(fmt.Errorf("Unknown value type %s", reflect.TypeOf(lhs)))
	}
	return
}

func compareGreaterThan(lhs, rhs interface{}) (r bool) {
	switch lhs.(type) {
	case string, bool:
		exprRaise(fmt.Errorf("Cannot compare %s types", reflect.TypeOf(lhs)))
	case int8, int16, int32, int64:
		r = reflect.ValueOf(lhs).Int() > reflect.ValueOf(rhs).Int()
	case uint8, uint16, uint32, uint64:
		r = reflect.ValueOf(lhs).Uint() > reflect.ValueOf(rhs).Uint()
	case float64:
		r = reflect.ValueOf(lhs).Float() > reflect.ValueOf(rhs).Float()
	case time.Time:
		r = lhs.(time.Time).UnixNano() > rhs.(time.Time).UnixNano()
	default:
		exprRaise(fmt.Errorf("Unknown value type %s", reflect.TypeOf(lhs)))
	}
	return
}

func compareGreaterThanEqualTo(lhs, rhs interface{}) (r bool) {
	switch lhs.(type) {
	case string, bool:
		exprRaise(fmt.Errorf("Cannot compare %s types", reflect.TypeOf(lhs)))
	case int8, int16, int32, int64:
		r = reflect.ValueOf(lhs).Int() >= reflect.ValueOf(rhs).Int()
	case uint8, uint16, uint32, uint64:
		r = reflect.ValueOf(lhs).Uint() >= reflect.ValueOf(rhs).Uint()
	case float64:
		r = reflect.ValueOf(lhs).Float() >= reflect.ValueOf(rhs).Float()
	case time.Time:
		r = lhs.(time.Time).UnixNano() >= rhs.(time.Time).UnixNano()
	default:
		exprRaise(fmt.Errorf("Unknown value type %s", reflect.TypeOf(lhs)))
	}
	return
}

func compareLike(lhs, rhs interface{}) (r bool) {
	switch lhs.(type) {
	case string:
		s := lhs.(string)
		pattern := rhs.(string)
		if strings.HasPrefix(pattern, "*") {
			if strings.HasSuffix(pattern, "*") {
				r = strings.Contains(s, pattern[1:len(pattern)-1])
			} else {
				r = strings.HasSuffix(s, pattern[1:])
			}
		} else if strings.HasSuffix(pattern, "*") {
			r = strings.HasPrefix(s, pattern[:len(pattern)-1])
		} else {
			r = s == pattern
		}
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64, bool, float64, time.Time:
		exprRaise(fmt.Errorf("Cannot compare %s types", reflect.TypeOf(lhs)))
	default:
		exprRaise(fmt.Errorf("Unknown value type %s", reflect.TypeOf(lhs)))
	}
	return
}

type evalContext struct {
	types       FieldTypeMap
	valueGetter FieldValueGetter
	stack       []interface{}
}

func (c *evalContext) pushIdentifier(ident string, t ValueType) {
	// This may all seem redundant to break everything out instead of just
	// using interface{}, but it's done this way quite on purpose to avoid
	// tiny allocations of interface{} everywhere that are just quickly
	// discarded.

	var err error
	switch t {
	case ValueTypeString:
		var v string
		if v, err = c.valueGetter.GetString(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeSignedInt8:
		var v int8
		if v, err = c.valueGetter.GetSignedInt8(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeSignedInt16:
		var v int16
		if v, err = c.valueGetter.GetSignedInt16(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeSignedInt32:
		var v int32
		if v, err = c.valueGetter.GetSignedInt32(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeSignedInt64:
		var v int64
		if v, err = c.valueGetter.GetSignedInt64(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeUnsignedInt8:
		var v uint8
		if v, err = c.valueGetter.GetUnsignedInt8(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeUnsignedInt16:
		var v uint16
		if v, err = c.valueGetter.GetUnsignedInt16(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeUnsignedInt32:
		var v uint32
		if v, err = c.valueGetter.GetUnsignedInt32(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeUnsignedInt64:
		var v uint64
		if v, err = c.valueGetter.GetUnsignedInt64(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeBool:
		var v bool
		if v, err = c.valueGetter.GetBool(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeDouble:
		var v float64
		if v, err = c.valueGetter.GetDouble(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	case ValueTypeTimestamp:
		var v time.Time
		if v, err = c.valueGetter.GetTimestamp(ident); err == nil {
			c.stack = append(c.stack, v)
		}
	}

	if err != nil {
		if _, ok := err.(FieldNotSet); ok {
			c.stack = append(c.stack, nil)
		} else {
			exprRaise(err)
		}
	}
}

func (c *evalContext) evaluateBinaryExpr(e *binaryExpr) {
	switch e.op {
	case binaryOpLogicalAnd:
		// if the lhs result is false, leave it on the stack and return
		// without evaluating the rhs; otherwise, pop the lhs result
		// and leave the rhs result
		c.evaluateNode(e.x)
		if v, ok := c.stack[len(c.stack)-1].(bool); !ok {
			exprRaise(fmt.Errorf("Type mismatch in logical-and: bool vs. %s",
				reflect.TypeOf(c.stack[len(c.stack)-1])))
		} else if v {
			c.stack = c.stack[0 : len(c.stack)-1]
			c.evaluateNode(e.y)
		}

	case binaryOpLogicalOr:
		// if the lhs result is true, leave it on the stack and return
		// without evaluating the lhs; otherwise, pop the lhs result
		// and leave the rhs result
		c.evaluateNode(e.x)
		if v, ok := c.stack[len(c.stack)-1].(bool); !ok {
			exprRaise(fmt.Errorf("Type mismatch in logical-or: bool vs. %s",
				reflect.TypeOf(c.stack[len(c.stack)-1])))
		} else if !v {
			c.stack = c.stack[0 : len(c.stack)-1]
			c.evaluateNode(e.y)
		}

	case binaryOpEQ, binaryOpNE, binaryOpLT, binaryOpLE, binaryOpGT, binaryOpGE, binaryOpLike:
		c.evaluateNode(e.x)
		c.evaluateNode(e.y)

		lhs := c.stack[len(c.stack)-2]
		rhs := c.stack[len(c.stack)-1]
		c.stack = c.stack[0 : len(c.stack)-1]

		var result bool

		// If either side of the comparison is NULL, the result is FALSE
		if lhs == nil || rhs == nil {
			result = false
		} else {
			if lt, rt := ValueTypeOf(lhs), ValueTypeOf(rhs); lt != rt {
				exprRaise(fmt.Errorf("Type mismatch in comparison: %s vs. %s",
					ValueTypeStrings[lt], ValueTypeStrings[rt]))
			}

			switch e.op {
			case binaryOpEQ:
				result = compareEqual(lhs, rhs)
			case binaryOpNE:
				result = compareNotEqual(lhs, rhs)
			case binaryOpLT:
				result = compareLessThan(lhs, rhs)
			case binaryOpLE:
				result = compareLessThanEqualTo(lhs, rhs)
			case binaryOpGT:
				result = compareGreaterThan(lhs, rhs)
			case binaryOpGE:
				result = compareGreaterThanEqualTo(lhs, rhs)
			case binaryOpLike:
				result = compareLike(lhs, rhs)
			default:
				panic("internal error: unreachable condition in evaluateBinaryExpr")
			}
		}

		c.stack[len(c.stack)-1] = result

	case binaryOpBitwiseAnd:
		c.evaluateNode(e.x)
		c.evaluateNode(e.y)

		lhs := c.stack[len(c.stack)-2]
		rhs := c.stack[len(c.stack)-1]
		c.stack = c.stack[0 : len(c.stack)-1]

		if lt, rt := ValueTypeOf(lhs), ValueTypeOf(rhs); lt != rt {
			exprRaise(fmt.Errorf("Type mismatch for &: %s vs. %s",
				ValueTypeStrings[lt], ValueTypeStrings[rt]))
		}

		switch lhs.(type) {
		case int8:
			c.stack[len(c.stack)-1] = lhs.(int8) & rhs.(int8)
		case int16:
			c.stack[len(c.stack)-1] = lhs.(int16) & rhs.(int16)
		case int32:
			c.stack[len(c.stack)-1] = lhs.(int32) & rhs.(int32)
		case int64:
			c.stack[len(c.stack)-1] = lhs.(int64) & rhs.(int64)
		case uint8:
			c.stack[len(c.stack)-1] = lhs.(uint8) & rhs.(uint8)
		case uint16:
			c.stack[len(c.stack)-1] = lhs.(uint16) & rhs.(uint16)
		case uint32:
			c.stack[len(c.stack)-1] = lhs.(uint32) & rhs.(uint32)
		case uint64:
			c.stack[len(c.stack)-1] = lhs.(uint64) & rhs.(uint64)
		default:
			exprRaise(fmt.Errorf("Type for & must be an integer; got %s",
				reflect.TypeOf(lhs)))
		}

	default:
		panic("internal error: unreachable condition in evaluateBinaryExpr")
	}
}

func (c *evalContext) evaluateUnaryExpr(e *unaryExpr) {
	switch e.op {
	case unaryOpIsNull:
		c.evaluateNode(e.x)
		c.stack[len(c.stack)-1] = c.stack[len(c.stack)-1] == nil

	case unaryOpIsNotNull:
		c.evaluateNode(e.x)
		c.stack[len(c.stack)-1] = c.stack[len(c.stack)-1] != nil

	case unaryOpNot:
		c.evaluateNode(e.x)
		c.stack[len(c.stack)-1] = !c.stack[len(c.stack)-1].(bool)

	default:
		panic("internal error: unreachable condition in evaluateUnaryExpr")
	}
}

func (c *evalContext) evaluateNode(e expr) {
	switch v := e.(type) {
	case *identExpr:
		c.pushIdentifier(v.name, v.t)
	case *valueExpr:
		c.stack = append(c.stack, v.v)
	case *binaryExpr:
		c.evaluateBinaryExpr(v)
	case *unaryExpr:
		c.evaluateUnaryExpr(v)
	default:
		panic("internal error: unreachable condition in evaluateNode")
	}
}

func (c *evalContext) evaluateExpression(e expr) (result interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	c.evaluateNode(e)
	if len(c.stack) != 1 {
		panic("internal error: stack in unexpected state after expression evaluation")
	}
	result = c.stack[0]
	return
}

func newEvalContext(types FieldTypeMap, valueGetter FieldValueGetter) evalContext {
	return evalContext{
		types:       types,
		valueGetter: valueGetter,
		stack:       make([]interface{}, 0, 8),
	}
}

func evaluateExpression(
	e expr,
	types FieldTypeMap,
	valueGetter FieldValueGetter,
) (interface{}, error) {
	c := newEvalContext(types, valueGetter)
	return c.evaluateExpression(e)
}
