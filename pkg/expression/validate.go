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
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

func validateIdentifier(ident string) error {
	if len(ident) == 0 {
		return errors.New("Invalid identifier: \"\"")
	}

	// First character must be letter or underscore
	if !(unicode.IsLetter(rune(ident[0])) || ident[0] == '_') {
		return errors.New("Identifiers must begin with letters or an underscore")
	}

	// Successive characters must be letters, digits, or underscore
	for _, r := range ident {
		if !(unicode.IsDigit(r) || unicode.IsLetter(r) || r == '_') {
			return errors.New("Identifiers must contain only letters, digits, or underscores")
		}
	}

	return nil
}

func validateBitwiseAnd(e *binaryExpr) {
	// lhs must be identifier; rhs must be an integer value
	if _, ok := e.x.(*identExpr); !ok {
		exprRaise(errors.New("BITWISE-AND lhs must be an identifier"))
	}
	if v, ok := e.y.(*valueExpr); !ok || !v.isInteger() {
		exprRaise(errors.New("BITWISE-AND rhs must be an integer value"))
	}
}

func validateKernelFilterNode(e expr) {
	switch node := e.(type) {
	case *identExpr:
		if err := validateIdentifier(node.name); err != nil {
			exprRaise(err)
		}

	case *valueExpr:
		vt := ValueTypeOf(node.v)
		switch {
		case vt.IsInteger():
			// ok
		case vt.IsString():
			// Strings passed to the kernel filter cannot contain
			// quotation mark characters. It is impossible to get
			// them recognized by the kernel's parser.
			if strings.IndexRune(node.v.(string), '"') != -1 {
				exprRaise(errors.New("String literals cannot contain QUOTATION MARK"))
			}
		default:
			exprRaise(errors.New("Value must be string or integer"))
		}

	case *binaryExpr:
		switch node.op {
		case binaryOpLogicalAnd, binaryOpLogicalOr:
			validateKernelFilterExpr(node.x)
			validateKernelFilterExpr(node.y)

		case binaryOpEQ:
			// lhs must be identifier; rhs must be value, can be any type
			if _, ok := node.x.(*identExpr); !ok {
				exprRaise(errors.New("Comparison lhs must be an identifier"))
			}
			if _, ok := node.y.(*valueExpr); !ok {
				exprRaise(errors.New("Comparison rhs must be a value"))
			}
			validateKernelFilterNode(node.x)
			validateKernelFilterNode(node.y)

		case binaryOpNE:
			// if lhs is bitwise-and, rhs must be integer value 0
			// if lhs is an identifier, rhs must be value of any type
			if x, ok := node.x.(*binaryExpr); ok && x.op == binaryOpBitwiseAnd {
				validateBitwiseAnd(x)

				var v *valueExpr
				v, ok = node.y.(*valueExpr)
				if !ok {
					exprRaise(errors.New("Rhs of comparison with bitwise-and must be 0"))
				}
				switch v.v.(type) {
				case int8, int16, int32, int64:
					if reflect.ValueOf(v.v).Int() != 0 {
						exprRaise(errors.New("Rhs of comparison with bitwise-and must be 0"))
					}
				case uint8, uint16, uint32, uint64:
					if reflect.ValueOf(v.v).Uint() != 0 {
						exprRaise(errors.New("Rhs of comparison with bitwise-and must be 0"))
					}
				default:
					exprRaise(errors.New("Rhs of comparison with bitwise-and must be 0"))
				}
			} else {
				if _, ok = node.x.(*identExpr); !ok {
					exprRaise(errors.New("Comparison lhs must be an identifier"))
				}
				if _, ok = node.y.(*valueExpr); !ok {
					exprRaise(errors.New("Comparison rhs must be a value"))
				}
				validateKernelFilterNode(node.x)
				validateKernelFilterNode(node.y)
			}

		case binaryOpLT, binaryOpLE, binaryOpGT, binaryOpGE:
			// lhs must be identifier; rhs must be value of integer type
			if _, ok := node.x.(*identExpr); !ok {
				exprRaise(errors.New("Comparison lhs must be an identifier"))
			}
			if v, ok := node.y.(*valueExpr); !ok || !v.isInteger() {
				exprRaise(errors.New("Comparison rhs must be an integer value"))
			}
			validateKernelFilterNode(node.x)
			validateKernelFilterNode(node.y)

		case binaryOpLike:
			// lhs must be identifier; rhs must be string value
			if _, ok := node.x.(*identExpr); !ok {
				exprRaise(errors.New("Comparison lhs must be an identifier"))
			}
			if v, ok := node.y.(*valueExpr); !ok || !v.isString() {
				exprRaise(errors.New("Comparison rhs must be a string value"))
			}
			validateKernelFilterNode(node.x)
			validateKernelFilterNode(node.y)
		}

	case *unaryExpr:
		switch node.op {
		case unaryOpNot:
			validateKernelFilterNode(node.x)
		}

	default:
		exprRaise(fmt.Errorf("Invalid expression type %s", reflect.TypeOf(e)))
	}
}

func validateKernelFilterExpr(e expr) {
	switch node := e.(type) {
	case *binaryExpr:
		if node.op == binaryOpBitwiseAnd {
			validateBitwiseAnd(node)
		} else {
			validateKernelFilterNode(e)
		}
	default:
		validateKernelFilterNode(e)
	}
}

func validateKernelFilterTree(e expr) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	validateKernelFilterExpr(e)
	return
}

func validateBinaryExprTypes(e *binaryExpr) (r ValueType) {
	switch e.op {
	case binaryOpLogicalAnd, binaryOpLogicalOr:
		lhs := validateExprTypes(e.x)
		if lhs != ValueTypeBool {
			exprRaise(fmt.Errorf("Lhs of AND/OR must be type BOOL; got %s",
				ValueTypeStrings[lhs]))
		}
		rhs := validateExprTypes(e.y)
		if rhs != ValueTypeBool {
			exprRaise(fmt.Errorf("Rhs of AND/OR must be type BOOL; got %s",
				ValueTypeStrings[rhs]))
		}
		r = ValueTypeBool

	case binaryOpEQ, binaryOpNE:
		lhs := validateExprTypes(e.x)
		rhs := validateExprTypes(e.y)
		if lhs != rhs {
			exprRaise(fmt.Errorf("Type mismatch (%s vs. %s)",
				ValueTypeStrings[lhs], ValueTypeStrings[rhs]))
		}
		r = ValueTypeBool

	case binaryOpLT, binaryOpLE, binaryOpGT, binaryOpGE:
		lhs := validateExprTypes(e.x)
		if !lhs.IsNumeric() {
			exprRaise(fmt.Errorf("Type for %s must be numeric; got %s",
				binaryOpStrings[e.op], ValueTypeStrings[lhs]))
		}
		rhs := validateExprTypes(e.y)
		if lhs != rhs {
			exprRaise(fmt.Errorf("Type mismatch (%s vs. %s)",
				ValueTypeStrings[lhs], ValueTypeStrings[rhs]))
		}
		r = ValueTypeBool

	case binaryOpLike:
		lhs := validateExprTypes(e.x)
		if !lhs.IsString() {
			exprRaise(fmt.Errorf("Type for LIKE must be STRING; got %s",
				ValueTypeStrings[lhs]))
		}
		rhs := validateExprTypes(e.y)
		if lhs != rhs {
			exprRaise(fmt.Errorf("Type mismatch (%s vs. %s)",
				ValueTypeStrings[lhs], ValueTypeStrings[rhs]))
		}
		r = ValueTypeBool

	case binaryOpBitwiseAnd:
		lhs := validateExprTypes(e.x)
		if !lhs.IsInteger() {
			exprRaise(fmt.Errorf("Type for %s must be an integer; got %s",
				binaryOpStrings[e.op], ValueTypeStrings[lhs]))
		}
		rhs := validateExprTypes(e.y)
		if lhs != rhs {
			exprRaise(fmt.Errorf("Type mismatch (%s vs. %s)",
				ValueTypeStrings[lhs], ValueTypeStrings[rhs]))
		}
		r = lhs
	default:
		exprRaise(fmt.Errorf("Illegal binary op type %d", e.op))
	}
	return
}

func validateUnaryExprTypes(e *unaryExpr) (r ValueType) {
	switch e.op {
	case unaryOpIsNull, unaryOpIsNotNull:
		validateExprTypes(e.x)
		r = ValueTypeBool
	case unaryOpNot:
		r = validateExprTypes(e.x)
		if r != ValueTypeBool {
			exprRaise(fmt.Errorf("Operand of NOT must be type BOOL; got %s",
				ValueTypeStrings[r]))
		}

	default:
		exprRaise(fmt.Errorf("Illegal unary op type %d", e.op))
	}
	return
}

func validateExprTypes(e expr) (r ValueType) {
	switch node := e.(type) {
	case *identExpr:
		r = node.t

	case *valueExpr:
		if t := ValueTypeOf(node.v); t != ValueTypeUnspecified {
			r = t
		} else {
			exprRaise(fmt.Errorf("Unsupported value type %s",
				reflect.TypeOf(node.v)))
		}

	case *binaryExpr:
		r = validateBinaryExprTypes(node)

	case *unaryExpr:
		r = validateUnaryExprTypes(node)
	default:
		exprRaise(fmt.Errorf("Unrecognized expression type %s", reflect.TypeOf(e)))
	}
	return
}

func validateTypes(e expr) (vt ValueType, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	vt = validateExprTypes(e)
	return
}
