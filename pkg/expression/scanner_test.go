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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func (s *scanner) errorWrapper(msg string) (r interface{}) {
	defer func() {
		r = recover()
	}()
	s.error(msg)
	return
}

func TestScannerError(t *testing.T) {
	s := scanner{
		offset:      923874,
		tokenOffset: 938475,
	}
	i := s.errorWrapper("error message")
	if assert.IsType(t, parseError{}, i) {
		e := i.(parseError)
		assert.Equal(t, s.offset-1, e.offset)
		assert.Equal(t, s.tokenOffset, e.tokenOffset)
	}
}

func (s *scanner) errorfWrapper(msg string, args ...interface{}) (r interface{}) {
	defer func() {
		r = recover()
	}()
	s.errorf(msg, args...)
	return
}

func TestScannerErrorf(t *testing.T) {
	s := scanner{
		offset:      923874,
		tokenOffset: 938475,
	}
	i := s.errorfWrapper("error %s", "message")
	if assert.IsType(t, parseError{}, i) {
		e := i.(parseError)
		assert.Equal(t, s.offset-1, e.offset)
		assert.Equal(t, s.tokenOffset, e.tokenOffset)
	}
}

func TestScannerNext(t *testing.T) {
	s := scanner{}
	r := s.next()
	if assert.False(t, r) {
		assert.Equal(t, rune(-1), s.r)
	}

	s = scanner{
		input: []byte{'a', 'b', 'c'},
	}
	for i, b := range s.input {
		r = s.next()
		if assert.True(t, r) {
			assert.Equal(t, i+1, s.offset)
			assert.Equal(t, rune(b), s.r)
		}
	}
	r = s.next()
	if assert.False(t, r) {
		assert.Equal(t, rune(-1), s.r)
	}

	s = scanner{
		input: []byte{0xe2, 0x82, 0xac}, // utf-8 encoding of U+20AC
	}
	r = s.next()
	if assert.True(t, r) {
		assert.Equal(t, 3, s.offset)
		assert.Equal(t, rune(0x20AC), s.r)
	}

	assert.Panics(t, func() {
		s = scanner{
			input: []byte{0},
		}
		s.next()
	})

	assert.Panics(t, func() {
		s = scanner{
			input: []byte{0x80, 0x20}, // illegal utf-8 sequence
		}
		s.next()
	})
}

func TestScannerPeek(t *testing.T) {
	s := scanner{}
	r := s.peek()
	assert.Equal(t, rune(-1), r)

	s = scanner{
		input: []byte{'a', 'b', 'c'},
	}
	for i := 0; i < 4; i++ {
		r = s.peek()
		assert.Equal(t, 0, s.offset)
		assert.Equal(t, 'a', r)
	}

	s = scanner{
		input: []byte{0xe2, 0x82, 0xac}, // utf-8 encoding of U+20AC
	}
	r = s.peek()
	assert.Equal(t, 0, s.offset)
	assert.Equal(t, rune(0x20AC), r)

	assert.Panics(t, func() {
		s = scanner{
			input: []byte{0},
		}
		s.peek()
	})

	assert.Panics(t, func() {
		s = scanner{
			input: []byte{0x80, 0x20}, // illegal utf-8 sequence
		}
		s.peek()
	})
}

func TestValueOf(t *testing.T) {
	for i, r := range "0123456789" {
		v := valueOf(r)
		assert.Equalf(t, i, v, "index %d (%c)", i, r)
	}
	for i, r := range "ABCDEF" {
		v := valueOf(r)
		assert.Equalf(t, i+10, v, "index %d (%c)", i, r)
	}
	for i, r := range "abcdef" {
		v := valueOf(r)
		assert.Equalf(t, i+10, v, "index %d (%c)", i, r)
	}

	assert.Equal(t, -1, valueOf('G'))
	assert.Equal(t, -1, valueOf('g'))
}

func TestScannerSkipWhitespace(t *testing.T) {
	s := scanner{
		input: []byte{' ', '\t', '\n', '\r', 'a'},
	}
	r := s.skipWhitespace()
	assert.True(t, r)
	assert.Equal(t, 4, s.offset)

	s = scanner{
		input: []byte{' ', ' ', ' '},
	}
	r = s.skipWhitespace()
	assert.False(t, r)
}

func TestScannerScanEscape(t *testing.T) {
	assert.Panics(t, func() {
		s := scanner{}
		s.scanEscape()
	})

	testCases := []struct {
		input  []byte
		expect rune
	}{
		{[]byte{'\\'}, '\\'},
		{[]byte{'"'}, '"'},
		{[]byte{'a'}, 0x07},
		{[]byte{'b'}, 0x08},
		{[]byte{'t'}, 0x09},
		{[]byte{'n'}, 0x0A},
		{[]byte{'v'}, 0x0B},
		{[]byte{'f'}, 0x0C},
		{[]byte{'r'}, 0x0D},
		{[]byte{'u', '2', '0', 'a', 'c'}, 0x20AC},
		{[]byte{'U', '0', '0', '0', '0', '2', '0', 'A', 'C'}, 0x20AC},
		{[]byte{'x', '7', 'F'}, 0x7F},
		{[]byte{'1', '7', '7'}, 0x7F},
	}
	for i, tc := range testCases {
		s := scanner{input: tc.input}
		got := s.scanEscape()
		assert.Equalf(t, tc.expect, got, "index %d", i)
	}

	// All of these cases should panic:
	badTestCases := [][]byte{
		[]byte{'c'},
		[]byte{'8'},
		[]byte{'x', '4'},
		[]byte{'U', '2', '0', 'A', 'C', 'u', 'r', 'o', '!', '!', '!'},
		[]byte{'U', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F'},
		[]byte{'u', 'd', '8', '0', '0'},
		[]byte{'u', 'd', 'e', '0', '0'},
	}
	for i, tc := range badTestCases {
		assert.Panicsf(t, func() {
			s := scanner{input: tc}
			s.scanEscape()
		}, "index %d", i)
	}
}

func TestScannerScanString(t *testing.T) {
	testCases := [][2]string{
		{"abc\"", "abc"},
		{"abc \\\"def\\\" ghi\"", "abc \"def\" ghi"},
	}
	for i, tc := range testCases {
		s := scanner{input: []byte(tc[0])}
		gotToken, gotText := s.scanString()
		assert.Equalf(t, tokenString, gotToken, "index %d (%s)", i, tc[0])
		assert.Equalf(t, tc[1], gotText, "index %d (%s)", i, tc[0])
	}

	assert.Panics(t, func() {
		s := scanner{}
		s.scanString()
	})
}

func TestScannerScanIdentifier(t *testing.T) {
	testCases := [][2]string{
		{"abc", "abc"},
		{"abc123(42)", "abc123"},
		{"abc_def_ghi - xyz", "abc_def_ghi"},
	}
	for i, tc := range testCases {
		s := scanner{input: []byte(tc[0])}
		s.next()
		gotToken, gotText := s.scanIdentifier()
		assert.Equal(t, tokenIdentifier, gotToken, "index %d (%s)", i, tc[0])
		assert.Equal(t, tc[1], gotText, "index %d (%s)", i, tc[0])
	}
}

func TestScanNumber(t *testing.T) {
	goodTestCases := []struct {
		input       string
		expectToken token
		expectText  string
	}{
		{"8 123", tokenInteger, "8"},
		{"0", tokenInteger, "0"},
		{"123", tokenInteger, "123"},
		{"0xdeadbeef", tokenInteger, "0xdeadbeef"},
		{"0X888", tokenInteger, "0X888"},
		{"0177", tokenInteger, "0177"},
		{"0374.78e12", tokenFloat, "0374.78e12"},
		{".123", tokenFloat, ".123"},
		{"0.3245", tokenFloat, "0.3245"},
		{"34857.432e-99", tokenFloat, "34857.432e-99"},
		{"342.1e+10", tokenFloat, "342.1e+10"},
	}
	for i, tc := range goodTestCases {
		s := scanner{input: []byte(tc.input)}
		s.next()
		gotToken, gotText := s.scanNumber()
		assert.Equal(t, tc.expectToken, gotToken, "index %d (%s)", i, tc.input)
		assert.Equal(t, tc.expectText, gotText, "index %d (%s)", i, tc.input)
	}

	badTestCases := []string{
		"0x",
		"01289",
		".",
		".e9",
		"0.123e",
		"0.123eABCD",
	}
	for i, tc := range badTestCases {
		assert.Panics(t, func() {
			s := scanner{input: []byte(tc)}
			s.next()
			s.scanNumber()
		}, "index %d (%s)", i, tc)
	}
}

func TestScannerNextToken(t *testing.T) {
	s := scanner{}
	_, tok, _ := s.nextToken()
	assert.Equal(t, tokenEOF, tok)

	assert.Panics(t, func() {
		s = scanner{input: []byte{'@'}} // unrecognized character in input
		s.nextToken()
	})

	testCases := []struct {
		input  string
		offset int

		expectedTokenOffset int
		expectedOffset      int
		expectedToken       token
		expectedText        string
	}{
		{"\"abc\"", 0, 0, 5, tokenString, "abc"},
		{"(foo)", 0, 0, 1, tokenLParen, "("},
		{"(foo)", 4, 4, 5, tokenRParen, ")"},
		{"-456", 0, 0, 1, tokenMinus, "-"},
		{"-456", 1, 1, 4, tokenInteger, "456"},
		{"a < b", 1, 2, 3, tokenLT, "<"},
		{"a <= b", 1, 2, 4, tokenLE, "<="},
		{"a > b", 1, 2, 3, tokenGT, ">"},
		{"a >= b", 1, 2, 4, tokenGE, ">="},
		{"a == b", 1, 2, 4, tokenEQ, "=="},
		{"a != 4", 1, 2, 4, tokenNE, "!="},
		{"!(a == b)", 0, 0, 1, tokenNot, "!"},
		{"a ~ \"*abc*\"", 1, 2, 3, tokenLike, "~"},
		{"a && b", 1, 2, 4, tokenLogicalAnd, "&&"},
		{"a & 0x80", 1, 2, 3, tokenBitwiseAnd, "&"},
		{"a || b", 1, 2, 4, tokenLogicalOr, "||"},
		{"foo != 23", 0, 0, 3, tokenIdentifier, "foo"},
	}
	for i, tc := range testCases {
		var (
			o    int
			text string
		)

		testCase := fmt.Sprintf("index %d (%s)", i, tc.input)
		s = scanner{
			input:  []byte(tc.input),
			offset: tc.offset,
		}
		o, tok, text = s.nextToken()
		assert.Equal(t, tc.expectedTokenOffset, s.tokenOffset, testCase)
		assert.Equal(t, tc.expectedTokenOffset, o, testCase)
		assert.Equal(t, tc.expectedOffset, s.offset, testCase)
		assert.Equal(t, tc.expectedToken, tok, testCase)
		assert.Equal(t, tc.expectedText, text, testCase)
	}
}
