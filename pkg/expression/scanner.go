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
	"strings"
	"unicode"
	"unicode/utf8"
)

// Currently the only mode for scanning is ParseModeKernelFilter. Therefore,
// the code here is written to support only that scanning mode. If/when other
// scanning modes are added, code changes may (will) be necessary to support
// them.

// The input is always treated as UTF-8 encoded and NUL runes are never allowed.

type scanner struct {
	input []byte    // immutable; input to be scanned
	mode  ParseMode // immutable; scanning mode to use

	r           rune // mutable; current rune
	offset      int  // mutable; next offset to read from
	tokenOffset int  // mutable; offset to start of current token
}

func (s *scanner) error(msg string) {
	panic(parseError{
		error:       errors.New(msg),
		offset:      s.offset - 1,
		tokenOffset: s.tokenOffset,
	})
}

func (s *scanner) errorf(msg string, args ...interface{}) {
	panic(parseError{
		error:       fmt.Errorf(msg, args...),
		offset:      s.offset - 1,
		tokenOffset: s.tokenOffset,
	})
}

func (s *scanner) next() bool {
	if s.offset >= len(s.input) {
		s.r = -1
		return false
	}

	s.r = rune(s.input[s.offset])
	switch {
	case s.r >= utf8.RuneSelf:
		var size int
		s.r, size = utf8.DecodeRune(s.input[s.offset:])
		s.offset += size
		if s.r == utf8.RuneError {
			s.r = -1
			s.error("illegal utf-8 encoding")
		}
	case s.r == 0:
		s.error("illegal NUL character in input")
	default:
		s.offset++
	}

	return true
}

func (s *scanner) peek() rune {
	if s.offset >= len(s.input) {
		return -1
	}

	r := rune(s.input[s.offset])
	switch {
	case r >= utf8.RuneSelf:
		r, _ = utf8.DecodeRune(s.input[s.offset:])
		if r == utf8.RuneError {
			s.error("illegal utf-8 encoding")
		}
	case r == 0:
		s.error("illegal NUL character in input")
	}

	return r
}

func valueOf(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'A' && r <= 'F':
		return 10 + int(r-'A')
	case r >= 'a' && r <= 'f':
		return 10 + int(r-'a')
	}
	return -1
}

func (s *scanner) skipWhitespace() bool {
	for {
		r := s.peek()
		if r == -1 {
			return false
		}
		if unicode.IsSpace(r) {
			s.next()
		} else {
			return true
		}
	}
}

func (s *scanner) scanEscape() rune {
	if !s.next() {
		s.error("unexpected end of input in escape sequence")
	}

	var (
		n         int
		base, max rune
	)
	switch s.r {
	case '\\':
		return '\\'
	case '"':
		return '"'
	case 'a':
		return '\a'
	case 'b':
		return '\b'
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'u':
		n, base, max = 4, 16, unicode.MaxRune
		s.next()
	case 'U':
		n, base, max = 8, 16, unicode.MaxRune
		s.next()
	case 'v':
		return '\v'
	case '0', '1', '2', '3', '4', '5', '6', '7':
		n, base, max = 3, 8, 255
	case 'x':
		n, base, max = 2, 16, 255
		s.next()
	default:
		s.error("unknown escape sequence")
	}

	r := rune(0)
	for {
		v := valueOf(s.r)
		if v == -1 || v > int(base) {
			s.errorf("illegal character %#U in escape sequence", s.r)
		}
		r = r*base + rune(v)

		n--
		if n == 0 {
			break
		}
		if !s.next() {
			s.error("unexpected end of input in escape sequence")
		}
	}
	if r < 0 || r > max || (r >= 0xD800 && r <= 0xDE00) {
		s.error("escape sequence yields invalid unicode codepoint")
	}
	return r
}

func (s *scanner) scanString() (token, string) {
	// s.r == '"'
	var parts []string
	offset := s.offset
	for {
		if !s.next() {
			s.error("unexpected end of input in string literal")
		}
		if s.r == '"' {
			parts = append(parts, string(s.input[offset:s.offset-1]))
			return tokenString, strings.Join(parts, "")
		}
		if s.r == '\\' {
			parts = append(parts, string(s.input[offset:s.offset-1]))
			parts = append(parts, string(s.scanEscape()))
			offset = s.offset
		}
	}
}

func (s *scanner) scanIdentifier() (token, string) {
	for {
		r := s.peek()
		if !unicode.In(r, unicode.L, unicode.Nl, unicode.Nd,
			unicode.Mn, unicode.Mc, unicode.Pc,
			unicode.Other_ID_Start, unicode.Other_ID_Continue) {
			break
		}
		s.next()
	}

	ident := string(s.input[s.tokenOffset:s.offset])
	return tokenIdentifier, ident
}

func (s *scanner) scanNumbersInBase(base int) (r rune) {
	for {
		r = s.peek()
		if r == -1 {
			return
		}
		if v := valueOf(r); v == -1 || v >= base {
			return
		}
		s.next()
	}
}

func (s *scanner) scanNumber() (token, string) {
	if s.r == '0' {
		r := s.peek()
		if r == 'x' || r == 'X' {
			s.next()
			s.scanNumbersInBase(16)
			if s.offset-s.tokenOffset == 2 {
				s.error("invalid hex number")
			}
			return tokenInteger, string(s.input[s.tokenOffset:s.offset])
		}
		// Octal or float
		r = s.scanNumbersInBase(8)
		if r == '8' || r == '9' {
			r = s.scanNumbersInBase(10)
			if r != '.' && r != 'e' && r != 'E' {
				s.error("invalid octal number")
			}
		} else if r != '.' && r != 'e' && r != 'E' {
			return tokenInteger, string(s.input[s.tokenOffset:s.offset])
		}
		// r == '.' || r == 'e' || r == 'E'
		s.next()
	} else if s.r != '.' {
		// s.r must be [0..9]
		r := s.scanNumbersInBase(10)
		if r != '.' && r != 'e' && r != 'E' {
			return tokenInteger, string(s.input[s.tokenOffset:s.offset])
		}
		s.next()
	}

	// At this point it's impossible to have anything other than a float.
	// s.r == '.' || s.r == 'e' || s.r == 'E'
	if s.r == '.' {
		r := s.scanNumbersInBase(10)
		if s.offset-s.tokenOffset == 1 {
			s.error("invalid floating point number")
		}
		if r != 'e' && r != 'E' {
			return tokenFloat, string(s.input[s.tokenOffset:s.offset])
		}
		s.next()
	}

	// s.r == 'e' || s.r == 'E'
	s.next()
	if s.r == '-' || s.r == '+' {
		s.next()
	}
	if v := valueOf(s.r); v == -1 || v >= 10 {
		s.error("invalid exponent")
	}
	s.scanNumbersInBase(10)
	return tokenFloat, string(s.input[s.tokenOffset:s.offset])
}

func (s *scanner) nextToken() (offset int, t token, text string) {
	if !s.skipWhitespace() {
		return s.offset, tokenEOF, ""
	}

	s.tokenOffset = s.offset
	offset = s.offset
	s.next()
	switch s.r {
	case '"':
		t, text = s.scanString()
	case '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		t, text = s.scanNumber()
	case '(':
		t, text = tokenLParen, "("
	case ')':
		t, text = tokenRParen, ")"
	case '-':
		t, text = tokenMinus, "-"
	case '<':
		if s.peek() == '=' {
			s.next()
			t, text = tokenLE, "<="
		} else {
			t, text = tokenLT, "<"
		}
	case '>':
		if s.peek() == '=' {
			s.next()
			t, text = tokenGE, ">="
		} else {
			t, text = tokenGT, ">"
		}
	case '!':
		if s.peek() == '=' {
			s.next()
			t, text = tokenNE, "!="
		} else {
			t, text = tokenNot, "!"
		}
	case '=':
		if s.peek() == '=' {
			s.next()
			t, text = tokenEQ, "=="
		}
	case '~':
		t, text = tokenLike, "~"
	case '&':
		if s.peek() == '&' {
			s.next()
			t, text = tokenLogicalAnd, "&&"
		} else {
			t, text = tokenBitwiseAnd, "&"
		}
	case '|':
		if s.peek() == '|' {
			s.next()
			t, text = tokenLogicalOr, "||"
		}
	default:
		if unicode.In(s.r, unicode.L, unicode.Nl, unicode.Other_ID_Start) {
			t, text = s.scanIdentifier()
		}
	}
	if t == tokenEOF {
		s.error("unrecognized character in input")
	}
	return
}
