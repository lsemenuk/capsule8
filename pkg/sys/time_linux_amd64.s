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

#include "textflag.h"

TEXT ·nanotime(SB),NOSPLIT,$0-8
	MOVQ	SP, BP		// Save SP

	MOVQ	·vdsoClockGettimeSym(SB), AX
	SUBQ	$16, SP		// Make space for results
	ANDQ	$-15, SP	// Align for C code
	MOVL	$1, DI		// CLOCK_MONOTONIC
	LEAQ	0(SP), SI
	CALL	AX
	MOVQ	0(SP), AX	// sec
	MOVQ	8(SP), DX	// nsec
	MOVQ	BP, SP		// Restore real SP

	// return (sec * 1e9) + nsec
	IMULQ	$1000000000, AX
	ADDQ	DX, AX
	MOVQ	AX, ret+0(FP)
	RET
