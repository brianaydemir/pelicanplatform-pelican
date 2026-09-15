/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

// Package ginctx is the fixture for the "ginContextAsContext" ruleguard
// rule in gorules/ginctx.go. It is deliberately full of violations.
//
// A ruleguard rule that compiles but matches nothing reports "0 issues",
// exactly like a clean tree, so the rule's own correctness is not
// observable from a repository-wide lint. This package makes it
// observable: .github/scripts/check-ruleguard-rules.sh lints this path and
// fails unless every line marked "want: ginctx" produces a diagnostic
// and every unmarked call stays silent.
//
// This directory is named "testdata", so Go's "..." expansion skips it:
// "go list ./gorules/..." matches nothing, and the repository-wide
// golangci-lint run never sees this file. Only an explicit path reaches
// it. Do not "fix" the violations below.
//
// The checker cross-checks the count below against gorules/ginctx.go,
// so adding a pattern there means updating it here:
//
// ruleguard-patterns: 8
package ginctx

import (
	"context"

	"github.com/gin-gonic/gin"
)

// One callee per argument position. Each takes eight parameters and
// declares context.Context at the position in its name.

func atPos1(ctx context.Context, a2, a3, a4, a5, a6, a7, a8 int)     {}
func atPos2(a1 int, ctx context.Context, a3, a4, a5, a6, a7, a8 int) {}
func atPos3(a1, a2 int, ctx context.Context, a4, a5, a6, a7, a8 int) {}
func atPos4(a1, a2, a3 int, ctx context.Context, a5, a6, a7, a8 int) {}
func atPos5(a1, a2, a3, a4 int, ctx context.Context, a6, a7, a8 int) {}
func atPos6(a1, a2, a3, a4, a5 int, ctx context.Context, a7, a8 int) {}
func atPos7(a1, a2, a3, a4, a5, a6 int, ctx context.Context, a8 int) {}
func atPos8(a1, a2, a3, a4, a5, a6, a7 int, ctx context.Context)     {}

// Negative controls. A callee that declares *gin.Context itself is the
// case the type pattern exists to spare, and "any" stands in for a
// parameter that merely sits where a context might have been.

func ginTyped(a1 int, c *gin.Context) {}
func takesAny(a1 int, v any)          {}

// Callee shapes other than a plain function, since m["f"].Type resolves
// differently for each: a method value, an interface method, and a
// func-typed variable.

type doer interface {
	Do(a1 int, ctx context.Context) error
}

type receiver struct{}

func (receiver) Method(a1 int, ctx context.Context) {}

// Handler is an ordinary gin handler holding a recycled *gin.Context.
func Handler(c *gin.Context) {
	atPos1(c, 2, 3, 4, 5, 6, 7, 8) // want: ginctx
	atPos2(1, c, 3, 4, 5, 6, 7, 8) // want: ginctx
	atPos3(1, 2, c, 4, 5, 6, 7, 8) // want: ginctx
	atPos4(1, 2, 3, c, 5, 6, 7, 8) // want: ginctx
	atPos5(1, 2, 3, 4, c, 6, 7, 8) // want: ginctx
	atPos6(1, 2, 3, 4, 5, c, 7, 8) // want: ginctx
	atPos7(1, 2, 3, 4, 5, 6, c, 8) // want: ginctx
	atPos8(1, 2, 3, 4, 5, 6, 7, c) // want: ginctx

	// Passing the request's own context is the fix, not a violation.
	atPos2(1, c.Request.Context(), 3, 4, 5, 6, 7, 8)

	// A callee that declares *gin.Context is handed the value on purpose.
	ginTyped(1, c)

	// The parameter is not a context.Context at all.
	takesAny(1, c)
}

// ViaMethod passes a recycled *gin.Context through a method value.
func ViaMethod(c *gin.Context) {
	var r receiver
	r.Method(1, c) // want: ginctx
}

// ViaInterface passes a recycled *gin.Context through an interface method.
func ViaInterface(d doer, c *gin.Context) {
	_ = d.Do(1, c) // want: ginctx
}

// ViaFuncVar passes a recycled *gin.Context through a func-typed variable.
func ViaFuncVar(fn func(a1 int, ctx context.Context), c *gin.Context) {
	fn(1, c) // want: ginctx
}
