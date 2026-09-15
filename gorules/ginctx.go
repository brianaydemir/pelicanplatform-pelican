//go:build ruleguard

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

// Package gorules holds ruleguard rules, run by gocritic's "ruleguard"
// checker under golangci-lint. See .golangci.yaml.
//
// The "ruleguard" build tag keeps these files out of ordinary builds.
// "go mod tidy" still sees them, because it loads packages with every
// build tag, and that is what keeps the go-ruleguard/dsl requirement in
// go.mod. The tag must not be "ignore", which is the one tag tidy does
// not satisfy.
//
// golangci-lint's cache does not key on these files, so after editing,
// clean the cache or use a scratch GOLANGCI_LINT_CACHE.
//
// Every file here is loaded by a glob in .golangci.yaml, so a new rule
// takes effect as soon as it is added, with no second place to name it.
// In exchange, each file must have a fixture at
// gorules/testdata/<file>/ that proves the rule still matches:
// .github/scripts/check-ruleguard-rules.sh fails on a rule that has
// none. A rule that loads cleanly and then matches nothing reports the
// same "0 issues" as a clean repository, so the fixture is the only
// thing that tells them apart.
package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// ginContextAsContext reports a *gin.Context passed to a parameter
// declared as context.Context.
//
// Gin returns the *gin.Context to a sync.Pool as soon as ServeHTTP
// returns, then overwrites c.Request on the next request that checks
// the pooled value out. Anything still holding the context and reading
// Done(), Err(), or Deadline() -- database/sql's awaitDone goroutine,
// net/http's cancel watcher, or a context.WithCancel derivative handed
// to a goroutine -- races against that write.
//
// Matching on the callee's signature is what keeps this quiet:
// a handoff to a helper that itself declares *gin.Context does not match,
// so the repo's gin-typed helpers are not reported.
//
// A pattern binds one argument position, so each position needs its own
// rule. The eight below cover the first through eighth arguments. The
// deepest context.Context parameter in this repository is the fifth,
// at origin_serve/metrics_file.go:46; positions six through eight are
// headroom. That survey bounds this repository only, so a dependency
// taking a context past the eighth argument would still slip through.
//
// Every pattern is exercised by gorules/testdata/ginctx, which
// .github/scripts/check-ruleguard-rules.sh lints in CI. That fixture
// declares how many patterns it covers, so adding one here without a
// case there fails the check. failOn in .golangci.yaml does not help:
// it covers loading only, and these patterns load fine whether or not
// they still match anything.
func ginContextAsContext(m dsl.Matcher) {
	m.Import(`github.com/gin-gonic/gin`)

	const report = `do not pass a *gin.Context where a context.Context is expected: gin recycles the Context once ServeHTTP returns, so later reads of it race with the next request; pass $ctx.Request.Context() instead`

	m.Match(`$f($ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func(context.Context, $*_) $*_`)).
		Report(report)

	m.Match(`$f($_, $ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func($_, context.Context, $*_) $*_`)).
		Report(report)

	m.Match(`$f($_, $_, $ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func($_, $_, context.Context, $*_) $*_`)).
		Report(report)

	m.Match(`$f($_, $_, $_, $ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func($_, $_, $_, context.Context, $*_) $*_`)).
		Report(report)

	m.Match(`$f($_, $_, $_, $_, $ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func($_, $_, $_, $_, context.Context, $*_) $*_`)).
		Report(report)

	m.Match(`$f($_, $_, $_, $_, $_, $ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func($_, $_, $_, $_, $_, context.Context, $*_) $*_`)).
		Report(report)

	m.Match(`$f($_, $_, $_, $_, $_, $_, $ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func($_, $_, $_, $_, $_, $_, context.Context, $*_) $*_`)).
		Report(report)

	m.Match(`$f($_, $_, $_, $_, $_, $_, $_, $ctx, $*_)`).
		Where(m["ctx"].Type.Is(`*gin.Context`) &&
			m["f"].Type.Is(`func($_, $_, $_, $_, $_, $_, $_, context.Context, $*_) $*_`)).
		Report(report)
}
