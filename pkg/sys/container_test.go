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

package sys

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHexDigit(t *testing.T) {
	xdigits := "0123456789abcdefABCDEF"
	for _, r := range xdigits {
		assert.Truef(t, isHexDigit(r), "digit %c", r)
	}

	notxdigits := "(*&^@#$%) ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ"
	for _, r := range notxdigits {
		assert.Falsef(t, isHexDigit(r), "rune %c", r)
	}
}

func TestIsSHA256(t *testing.T) {
	assert.False(t, isSHA256("this is not a sha256"))
	assert.False(t, isSHA256("ABCDEF2345789abc"))
	assert.False(t, isSHA256("aaa bbb ccc ddd eee fff ggg hhh iii jjj kkk lll mmm nnn ooo ppp "))

	h := sha256.Sum256([]byte{8, 8, 8, 8, 8, 8, 8, 8, 8})
	assert.True(t, isSHA256(hex.EncodeToString(h[:])))
}

func TestContainerID(t *testing.T) {
	h := sha256.Sum256([]byte{8, 8, 8, 8, 8, 8, 8, 8, 8})
	id := hex.EncodeToString(h[:])

	tests := []struct {
		s string
		e string
	}{
		{
			s: id,
			e: id,
		},
		{
			s: id + "-docker",
			e: id,
		},
		{
			s: "docker-" + id,
			e: id,
		},
		{
			s: "/docker/" + id,
			e: id,
		},

		// Not Container IDs
		{s: "asdfasdf"},
		{s: "aaaa" + id},
		{s: id + "aaaa"},
		{s: ""},
		{s: "/"},
		{s: "/init.scope"},
	}
	for _, tc := range tests {
		got := ContainerID(tc.s)
		assert.Equalf(t, tc.e, got, "%s", tc.s)
	}
}
