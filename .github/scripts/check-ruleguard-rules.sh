#!/usr/bin/env sh

# Verify that every ruleguard rule in "gorules" still fires.
#
# A rule that loads cleanly but matches nothing reports "0 issues",
# exactly like a clean repository, so golangci-lint cannot tell a
# working rule from a dead one and "failOn" does not help: it only
# covers loading. This script lints a fixture of deliberate violations
# per rule and fails unless every line marked "want: <rule>" produces a
# diagnostic and no unmarked line does.
#
# The convention, which this script enforces in both directions:
#
#   gorules/<rule>.go            the rule
#   gorules/testdata/<rule>/     its fixture, marked "// want: <rule>"
#
# A rule with no fixture is a failure, not an omission. That is the
# point: adding a rule without coverage has to be the thing that turns
# CI red, because nobody goes looking at a linter that appears to work.
#
# Usage: check-ruleguard-rules.sh
#
# Requires "golangci-lint" on PATH. In CI, golangci-lint-action puts it
# there; locally, a manual install does -- the same one AGENTS.md
# already assumes for "golangci-lint run".
#
# The pre-commit "golangci-lint" hook does not satisfy this, however
# much it looks like it should. That hook is "language: golang", so
# pre-commit builds the binary into an environment private to that hook
# and prepends it to PATH only while that hook runs. This script runs as
# a "language: system" hook and sees the ambient PATH, which is why the
# message below asks for an install a contributor may believe they
# already have.

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

RULES_DIR="gorules"
FIXTURE_ROOT="gorules/testdata"

if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "check-ruleguard-rules: golangci-lint is not on PATH." >&2
  echo "  The rules cannot be verified, so this is a failure, not a skip." >&2
  exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/ruleguard_check.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

status=0
note() {
  echo "check-ruleguard-rules: $1" >&2
  status=1
}

hint() {
  echo "  $1" >&2
}

# --- Pair every rule with a fixture, in both directions. ---

rules_files=$(find "$RULES_DIR" -maxdepth 1 -name '*.go' | sort)
if [ -z "$rules_files" ]; then
  echo "check-ruleguard-rules: no rule files in $RULES_DIR." >&2
  exit 1
fi

pkgs=""
for rules in $rules_files; do
  name=$(basename "$rules" .go)
  if [ -d "$FIXTURE_ROOT/$name" ]; then
    pkgs="$pkgs ./$FIXTURE_ROOT/$name/..."
  else
    note "$rules has no fixture."
    hint "Create $FIXTURE_ROOT/$name/ holding at least one call the rule"
    hint "must report, marked '// want: $name'. Without one, nothing can"
    hint "tell whether this rule still matches anything."
  fi
done

for dir in "$FIXTURE_ROOT"/*/; do
  [ -d "$dir" ] || continue
  name=$(basename "$dir")
  if [ ! -f "$RULES_DIR/$name.go" ]; then
    note "$dir has no rule; expected $RULES_DIR/$name.go."
    hint "Remove the fixture, or name it after the rule it covers."
  fi
done

[ "$status" -eq 0 ] || exit 1

# --- Lint every fixture in one cold-cache run. ---
#
# golangci-lint caches gocritic's results per analyzed package, and the
# cache key does not include the rule files. A warm cache therefore
# replays the previous run's diagnostics for an unchanged fixture and
# reports success even when a rule has been broken. Always start cold.
#
# The run also depends on "issues.max-same-issues: 0" in the config it
# names. Every diagnostic from one rule carries that rule's single
# "report" string, so the default cap of 3 would hide all but the first
# few and the comparison below would read the hidden ones as a rule that
# had stopped matching. See the comment on that setting.

set +e
# shellcheck disable=SC2086  # $pkgs is a list of package paths, not one word
output=$(GOLANGCI_LINT_CACHE="$WORK/cache" golangci-lint run \
  --config=.golangci.yaml $pkgs 2>&1)
rc=$?
set -e

dump() {
  echo >&2
  echo "--- golangci-lint output (exit $rc) ---" >&2
  echo "$output" >&2
}

# Any status but "clean" (0) or "issues found" (1) means the linter
# itself failed: a rule that would not load, a bad config, a load error.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  note "golangci-lint exited $rc; it did not run to completion."
  dump
  exit 1
fi
if echo "$output" | grep -q '^level=error'; then
  note "golangci-lint reported an error."
  dump
  exit 1
fi

# --- Check each rule against its fixture. ---

checked=0
for rules in $rules_files; do
  name=$(basename "$rules" .go)
  dir="$FIXTURE_ROOT/$name"

  # Marked lines and reported lines, as "file:line" pairs so a fixture
  # may grow to more than one file. Sorted lexically because that is the
  # order "comm" requires; differences are put back in numeric order for
  # reading.
  grep -rnE "// want: $name\$" "$dir" | cut -d: -f1,2 | sort -u \
    >"$WORK/expected"
  echo "$output" | grep -E "^$dir/.*:[0-9]+:[0-9]+: " \
    >"$WORK/diagnostics" || true
  cut -d: -f1,2 <"$WORK/diagnostics" | sort -u >"$WORK/actual"

  if [ ! -s "$WORK/expected" ]; then
    note "$dir has no '// want: $name' markers, so it proves nothing."
    continue
  fi

  if ! cmp -s "$WORK/expected" "$WORK/actual"; then
    note "$name: reported lines do not match its fixture."
    comm -23 "$WORK/expected" "$WORK/actual" | sort -t: -k2 -n \
      >"$WORK/missing"
    comm -13 "$WORK/expected" "$WORK/actual" | sort -t: -k2 -n \
      >"$WORK/extra"
    if [ -s "$WORK/missing" ]; then
      hint "marked, but nothing was reported there --"
      hint "the rule has most likely stopped matching:"
      while IFS= read -r loc; do
        hint "    $loc"
      done <"$WORK/missing"
    fi
    if [ -s "$WORK/extra" ]; then
      # Every rule is loaded against every fixture, so this is also how
      # another rule matching inside this fixture shows up. The message
      # text says which rule it was.
      hint "reported, but not marked -- either the rule is too broad,"
      hint "or another rule also matches here:"
      while IFS= read -r loc; do
        hint "    $(grep -F "$loc:" "$WORK/diagnostics" | head -1)"
      done <"$WORK/extra"
    fi
  fi

  # Every diagnostic in a fixture must come from ruleguard, not from
  # some other linter that happens to dislike the deliberate violations.
  if grep -qv 'ruleguard:' "$WORK/diagnostics"; then
    note "$name: a diagnostic in $dir did not come from ruleguard."
  fi

  # Drift guard. The fixture states how many patterns it covers, so
  # adding a pattern to the rule forces a deliberate edit here; without
  # it a new pattern would ship with nothing exercising it.
  declared=$(grep -rhoE '// ruleguard-patterns: [0-9]+' "$dir" |
    grep -oE '[0-9]+' | head -1)
  # "grep -c" exits 1 on a zero count, and under "set -e" an assignment
  # from a failing command substitution ends the script right here --
  # before any note, before the dump, so the run fails having said
  # nothing at all. A rule with no patterns is a finding to report, not
  # a reason to die, so keep going and let the zero reach the check
  # below. MatchComment declares a pattern just as Match does.
  patterns=$(grep -cE 'm\.Match(Comment)?\(' "$rules" || true)
  patterns=${patterns:-0}
  if [ "$patterns" -eq 0 ]; then
    note "$rules declares no ruleguard patterns."
    hint "A rule with no m.Match or m.MatchComment call cannot fire, so"
    hint "its fixture proves nothing. Add a pattern, or drop the rule."
  elif [ -z "$declared" ]; then
    note "$dir does not declare '// ruleguard-patterns: N'."
    hint "$rules has $patterns. Add the line to the fixture so that a"
    hint "new pattern cannot ship with nothing exercising it."
  elif [ "$declared" -ne "$patterns" ]; then
    note "$name: $rules has $patterns pattern(s), $dir declares $declared."
    hint "Every pattern needs a case in the fixture."
  fi

  checked=$((checked + 1))
done

if [ "$status" -ne 0 ]; then
  dump
  exit 1
fi

echo "check-ruleguard-rules: OK -- $checked rule(s) verified against their fixtures."
