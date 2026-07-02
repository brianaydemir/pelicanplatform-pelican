#!/usr/bin/env python3
"""Analyze JUnit XML artifacts from the scheduled ``-race`` test workflows.

Under ``-race`` the vast majority of "failures" are data races rather than
genuine test failures, and a single racy background goroutine can fail hundreds
of otherwise-unrelated tests. This script separates the two so the job summary
highlights genuine failures instead of drowning in race noise.

When a failure body carries *both* a race marker and genuine-failure evidence (a
testify ``Error Trace:`` or a column-0 ``panic:``/``fatal error:``), the genuine
failure takes precedence and is surfaced -- the race is usually in an unrelated
background goroutine or even a child process, so letting the race marker win
would silently bury a real bug (see ``has_genuine_failure_evidence``).

Downloads JUnit artifacts via ``gh`` from the last N completed runs of a workflow
(plus the current run when inside Actions), laid out as
``<artifacts-dir>/run-<run_id>/<artifact-name>/*.xml``; runs already on disk are
skipped. Then writes a summary (race total + itemized genuine FAILs + one re-run
command per package) and a detailed Markdown report.
"""

from __future__ import annotations

import argparse
import os
import subprocess  # nosec B404  # used with fixed argv and no shell (see run_gh)
import sys
import xml.etree.ElementTree as ET  # nosec B405  # XML is from our own CI runner, not user input
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

# Classification labels.
RACE = "race"
NON_RACE = "non_race"
# A failure whose body has a race marker *and* independent genuine-failure
# evidence: a real failure that also happened to trip a race. Surfaced as a
# genuine failure (not race noise), but tagged so the co-occurring race is visible.
RACE_WITH_FAILURE = "race_with_failure"

# A failure is race-caused if its captured output contains either of these
# markers. Both are needed: because a race can be reported from a background
# goroutine, some failing tests carry the Go testing verdict without the raw
# "WARNING: DATA RACE" block appearing in their own captured output (and vice
# versa).
RACE_MARKERS = (
    "WARNING: DATA RACE",
    "race detected during execution of test",
)

# Sentinels that a failure body holds genuine (non-race) failure evidence, used to
# rescue real failures that also tripped a race. testify assert/require always
# print an "Error Trace:" line, which never appears in Go race-detector output.
TESTIFY_FAILURE_MARKER = "Error Trace:"
# Go prints a genuine top-level panic/fatal at column 0; race-stack frames and
# subprocess logs embedded under a testify "Messages:" block are always indented.
# See has_genuine_failure_evidence for why these are matched at raw line-start.
LINE_START_FAILURE_MARKERS = ("panic:", "fatal error:")

# Go import-path prefix stripped from package names for display.
MODULE_PREFIX = "github.com/pelicanplatform/pelican/"

# Fallbacks for run links when the GITHUB_* env vars are unset (local CLI runs).
DEFAULT_SERVER_URL = "https://github.com"
DEFAULT_REPOSITORY = "PelicanPlatform/pelican"

# ``-count`` for the local re-run commands: high enough to expose a flaky failure,
# cheap because it re-runs one test, not the whole suite.
LOCAL_RERUN_COUNT = 10


def short_package(classname: str) -> str:
    """Strip the module prefix from a Go package path for readable display."""
    if classname.startswith(MODULE_PREFIX):
        return classname[len(MODULE_PREFIX) :]
    return classname


def has_genuine_failure_evidence(body: str) -> bool:
    """Whether ``body`` shows a real (non-race) failure via a precise sentinel.

    Deliberately high-precision over high-recall: every marker here is one that
    does not appear in Go race-detector output, so a race body is never mistaken
    for a genuine failure. The trade-off is that a genuine failure signalled only
    by a bare ``t.Errorf``/``t.Fatalf`` message (no testify trace, no top-level
    panic) is not detected; catching those would require heuristics that drag race
    noise back into the actionable list, defeating the point.
    """
    if TESTIFY_FAILURE_MARKER in body:
        return True
    # Match on the RAW line -- do NOT ``.strip()``. testify embeds a failing
    # subprocess's whole log (including its own indented "panic:" and nested
    # "WARNING: DATA RACE" blocks) under a tab-indented "Messages:" section;
    # stripping would promote that embedded child-process panic to a false
    # genuine-failure signal. A genuine top-level panic/fatal sits at column 0.
    for line in body.splitlines():
        if line.startswith(LINE_START_FAILURE_MARKERS):
            return True
    return False


def classify_failure_body(body: str | None) -> str:
    """Classify a failure's output as ``RACE``, ``RACE_WITH_FAILURE`` or ``NON_RACE``.

    Genuine-failure evidence takes precedence over a co-occurring race marker, so a
    real failure that also tripped a background/child-process race surfaces (as
    ``RACE_WITH_FAILURE``) instead of being buried in the race total.
    """
    if not body:
        return NON_RACE
    is_race = any(marker in body for marker in RACE_MARKERS)
    if has_genuine_failure_evidence(body):
        return RACE_WITH_FAILURE if is_race else NON_RACE
    return RACE if is_race else NON_RACE


@dataclass(frozen=True)
class TestIdentity:
    """Identifies a failing test. Includes the package so that same-named tests
    in different packages (e.g. ``TestBrokerApi``) never merge."""

    package: str  # full Go package path, from <testcase classname="...">
    name: str  # leaf test name, incl. subtest path, from <testcase name="...">

    def __str__(self) -> str:
        pkg = short_package(self.package)
        return f"{pkg}.{self.name}" if pkg else self.name


@dataclass
class RawTestcase:
    """A failing ``<testcase>`` from a single XML file, pre-folding."""

    package: str
    name: str
    classification: str


@dataclass
class Failure:
    """One occurrence of a leaf failure, tied to the run it happened in."""

    identity: TestIdentity
    classification: str
    run_id: str


@dataclass
class TestReport:
    """Aggregated failures for one (identity, classification) across all runs.

    ``raced_run_ids`` is populated only on the merged genuine reports produced by
    ``merge_genuine_by_identity`` (empty on the per-classification reports from
    ``aggregate``); it records which of the runs also carried a co-occurring race.
    """

    identity: TestIdentity
    classification: str
    run_ids: set = field(default_factory=set)
    raced_run_ids: set = field(default_factory=set)

    def run_count(self) -> int:
        return len(self.run_ids)

    def raced_count(self) -> int:
        return len(self.raced_run_ids)

    def sorted_run_ids(self) -> list:
        """Run ids most-recent first (numeric ids sort descending)."""

        def key(run_id: str):
            try:
                return (0, -int(run_id))
            except ValueError:
                return (1, run_id)

        return sorted(self.run_ids, key=key)

    def top_urls(self, server_url: str, repository: str, max_urls: int = 3) -> list:
        """Up to ``max_urls`` links to the most recent runs with this failure."""
        base = server_url.rstrip("/")
        return [
            f"{base}/{repository}/actions/runs/{run_id}"
            for run_id in self.sorted_run_ids()[:max_urls]
        ]


def fold_parent_rollups(rows: list[RawTestcase]) -> list[RawTestcase]:
    """Drop parent roll-up rows, keeping only leaf failures.

    A failing ``TestX`` whose subtest ``TestX/sub`` also failed shows up as its
    own (usually empty-bodied) ``<testcase>``; the real content lives in
    ``TestX/sub``. Classifying the empty parent would miscount it as non-race, so
    we drop any failing row whose name is a strict ``/``-prefix of another
    failing row's name *within the same package*.

    Folding is by name only and never inspects the classification. Accepted
    limitation: on the rare occasion a genuine assertion fires at the *parent*
    level while the surviving child failed only from race noise, dropping the
    parent can still mask that genuine failure.
    """
    by_pkg: dict[str, list[RawTestcase]] = {}
    for row in rows:
        by_pkg.setdefault(row.package, []).append(row)

    leaves: list[RawTestcase] = []
    for prows in by_pkg.values():
        names = [r.name for r in prows]
        for row in prows:
            prefix = row.name + "/"
            if any(other != row.name and other.startswith(prefix) for other in names):
                continue  # parent roll-up: a more specific failure exists
            leaves.append(row)
    return leaves


def parse_failing_rows(path: Path) -> list[RawTestcase]:
    """Stream one JUnit XML file (they can be ~130 MB) and return failing testcases.

    A truncated file yields the rows parsed before the truncation.
    """
    rows: list[RawTestcase] = []
    try:
        # nosec B314 -- XML is from our own CI runner, not user input.
        for _event, elem in ET.iterparse(str(path), events=("end",)):
            tag = elem.tag
            if tag == "testcase":
                node = elem.find("failure")
                if node is None:
                    node = elem.find("error")
                if node is not None:
                    rows.append(
                        RawTestcase(
                            package=elem.get("classname") or "",
                            name=elem.get("name") or "",
                            classification=classify_failure_body(node.text),
                        )
                    )
                elem.clear()  # body already read; free it (bounds memory to one body)
            elif tag == "testsuite":
                elem.clear()
    except ET.ParseError:
        pass  # keep whatever we parsed before the file was truncated
    return rows


def failures_from_file(path: Path, run_id: str) -> list[Failure]:
    """Parse and fold one file into leaf ``Failure`` occurrences."""
    leaves = fold_parent_rollups(parse_failing_rows(path))
    return [
        Failure(TestIdentity(r.package, r.name), r.classification, run_id)
        for r in leaves
    ]


def iter_all_failures(artifacts_dir: Path, verbose: bool = False) -> Iterator[Failure]:
    """Walk ``run-*/junit-*/*.xml`` and yield every leaf failure occurrence."""
    artifacts_dir = Path(artifacts_dir)
    if not artifacts_dir.exists():
        if verbose:
            print(f"warning: no artifacts directory at {artifacts_dir}", file=sys.stderr)
        return

    for run_dir in sorted(artifacts_dir.iterdir()):
        if not run_dir.is_dir():
            continue
        name = run_dir.name
        run_id = name[len("run-") :] if name.startswith("run-") else name

        for artifact_dir in sorted(run_dir.iterdir()):
            if not artifact_dir.is_dir() or not artifact_dir.name.startswith("junit-"):
                continue
            for xml_file in sorted(artifact_dir.glob("*.xml")):
                try:
                    yield from failures_from_file(xml_file, run_id)
                except OSError as exc:
                    if verbose:
                        print(f"warning: skipping {xml_file}: {exc}", file=sys.stderr)


def aggregate(failures: Iterable[Failure]) -> list[TestReport]:
    """Group failures by (identity, classification), deduping runs.

    Using a ``set`` of run ids means a test that failed in both matrix variants
    (e.g. ``pelican`` and ``pelican-server``) of the same run counts once.
    """
    groups: dict[tuple, TestReport] = {}
    for failure in failures:
        key = (failure.identity, failure.classification)
        report = groups.get(key)
        if report is None:
            report = TestReport(identity=failure.identity, classification=failure.classification)
            groups[key] = report
        report.run_ids.add(failure.run_id)
    return list(groups.values())


def summary_race_total(reports: Iterable[TestReport]) -> int:
    """Total pure-race occurrences (distinct runs) across all reports.

    Excludes ``RACE_WITH_FAILURE``: those are surfaced as genuine failures, not
    folded into the race-noise total.
    """
    return sum(r.run_count() for r in reports if r.classification == RACE)


def nonrace_reports(reports: Iterable[TestReport]) -> list[TestReport]:
    return [r for r in reports if r.classification == NON_RACE]


def genuine_reports(reports: Iterable[TestReport]) -> list[TestReport]:
    """Reports for real failures: plain non-race plus race-with-failure."""
    return [r for r in reports if r.classification in (NON_RACE, RACE_WITH_FAILURE)]


def merge_genuine_by_identity(reports: Iterable[TestReport]) -> list[TestReport]:
    """Collapse each test's ``NON_RACE`` and ``RACE_WITH_FAILURE`` reports into one.

    A test can be genuine-with-race in some runs and genuine-without-race in others;
    merging by identity lists it once (run count = distinct genuine runs) instead of
    fragmenting it across sections. ``raced_run_ids`` on the result records which of
    those runs also carried a race, for the "also raced" tag.
    """
    merged: dict[TestIdentity, TestReport] = {}
    for r in genuine_reports(reports):
        m = merged.get(r.identity)
        if m is None:
            m = TestReport(identity=r.identity, classification=NON_RACE)
            merged[r.identity] = m
        m.run_ids |= r.run_ids
        if r.classification == RACE_WITH_FAILURE:
            m.raced_run_ids |= r.run_ids
    return list(merged.values())


def _by_count_then_name(report: TestReport):
    return (-report.run_count(), str(report.identity))


def _also_raced_tag(report: TestReport) -> str:
    """`` ⚠ also raced ...`` suffix for a merged genuine report, else empty."""
    if report.raced_count():
        return f"  ⚠ also raced in {report.raced_count()} of {report.run_count()} run(s)"
    return ""


def _top_level_test(name: str) -> str:
    """The top-level test name (first ``/`` segment) for a ``-run`` filter.

    Targeting the parent re-runs the failing subtest too, and sidesteps Go's
    fiddly subtest matching (spaces rewritten to ``_``, per-segment anchoring).
    """
    return name.split("/", 1)[0]


def reproduce_command(
    identity: TestIdentity, race: bool = False, count: int = LOCAL_RERUN_COUNT
) -> str:
    """A copy-pasteable ``go test`` command that re-runs just this test locally.

    Uses the full package import path (runnable from anywhere in the module) and
    anchors the test name. Without ``-race`` this is the disambiguator: if the test
    still fails the failure is genuine, if it passes the failure was
    race-attributable. Pass ``race=True`` to reproduce the original race instead.
    """
    package = identity.package or "./..."
    race_flag = "-race " if race else ""
    return (
        f"go test {race_flag}-count={count} "
        f"-run '^{_top_level_test(identity.name)}$' {package}"
    )


def commands_by_package(
    reports: Iterable[TestReport], count: int = LOCAL_RERUN_COUNT
) -> list[tuple[str, str]]:
    """One local re-run command per package covering all its failing tests.

    Collapses subtests to their top-level parent, dedupes, and emits a ``go test``
    ``-run`` alternation over them. Returns ``(display_package, command)`` sorted by
    display name; the command keeps the full import path so it runs from anywhere.
    """
    tops_by_pkg: dict[str, set[str]] = {}
    for r in reports:
        tops_by_pkg.setdefault(r.identity.package, set()).add(
            _top_level_test(r.identity.name)
        )
    out: list[tuple[str, str]] = []
    for package in sorted(tops_by_pkg, key=short_package):
        alt = "|".join(sorted(tops_by_pkg[package]))
        cmd = f"go test -count={count} -run '^({alt})$' {package or './...'}"
        out.append((short_package(package), cmd))
    return out


def _repro_help_lines() -> list[str]:
    """Explanatory preamble for the local re-run commands in the detail report."""
    return [
        "> **Disambiguating a failure locally.** These runs use `-race`, which fails",
        "> a test on *any* data race — often one in an unrelated background goroutine.",
        "> To tell a genuine failure from race noise, re-run just that test **without**",
        "> `-race` (the `go test` command is listed under each test below):",
        ">",
        "> - **still fails** → genuine failure (flaky if it fails only some of the runs;",
        ">   raise `-count` to sample harder).",
        "> - **always passes** → the failure was race-attributable.",
        ">",
        "> Add `-race -v` to the command to reproduce the original race with full",
        "> output. The commands under *Race-only failures* double as a recall check: if",
        "> one fails without `-race`, it was a genuine failure the text heuristics missed.",
        "",
    ]


def render_step_summary(race_total: int, genuine: list[TestReport]) -> str:
    """Render the ``$GITHUB_STEP_SUMMARY`` body: the race-noise total, itemized
    genuine failures, and one per-package re-run command."""
    lines = ["## Scheduled test failure summary", ""]
    lines.append(f"**Race FAILs:** {race_total}  (occurrences across all analyzed runs)")
    lines.append("")

    genuine_total = sum(r.run_count() for r in genuine)
    lines.append(f"**Genuine / non-race FAILs:** {genuine_total}")
    lines.append("")
    if genuine:
        for report in sorted(genuine, key=_by_count_then_name):
            lines.append(f"- {report.run_count()}× {report.identity}{_also_raced_tag(report)}")
    else:
        lines.append("None.")
    lines.append("")

    if genuine:
        lines.append("## Re-run failing tests locally")
        lines.append("")
        lines.append(
            "> Re-run a test **without** `-race` to disambiguate: still fails → "
            "genuine (flaky if it fails only some runs; raise `-count`); always "
            "passes → race-attributable. Add `-race -v` to reproduce the original race."
        )
        lines.append("")
        for display_pkg, cmd in commands_by_package(genuine):
            lines.append(f"- {display_pkg}:")
            lines.append("  ```")
            lines.append(f"  {cmd}")
            lines.append("  ```")
        lines.append("")
    return "\n".join(lines)


def _render_section(
    title: str,
    reports: list[TestReport],
    server_url: str,
    repository: str,
    max_urls: int,
) -> list[str]:
    lines = [f"## {title} ({len(reports)})", ""]
    if not reports:
        lines.append("No failures found.")
        lines.append("")
        return lines
    for report in sorted(reports, key=_by_count_then_name):
        lines.append(
            f"- {report.identity} — failed in {report.run_count()} run(s)"
            f"{_also_raced_tag(report)}"
        )
        lines.append("  ```")
        lines.append(f"  {reproduce_command(report.identity)}")
        lines.append("  ```")
        for url in report.top_urls(server_url, repository, max_urls):
            lines.append(f"  - {url}")
    lines.append("")
    return lines


def render_detail_report(
    reports: Iterable[TestReport],
    server_url: str,
    repository: str,
    max_urls: int = 3,
) -> str:
    """Render the detailed Markdown report uploaded as an artifact.

    Genuine failures (non-race + race-with-failure) are merged per test so each
    appears once; pure-race failures get their own section.
    """
    reports = list(reports)
    genuine = merge_genuine_by_identity(reports)
    race = [r for r in reports if r.classification == RACE]

    lines = ["# Test failure analysis", ""]
    lines += _repro_help_lines()
    lines += _render_section("Genuine failures", genuine, server_url, repository, max_urls)
    lines += _render_section("Race-only failures", race, server_url, repository, max_urls)
    return "\n".join(lines)


@dataclass
class Config:
    artifacts_dir: Path
    summary_file: Path
    report_file: Path
    server_url: str
    repository: str
    max_urls: int
    verbose: bool
    step_summary_file: Path | None
    workflow: str | None
    limit: int
    current_run_id: str | None


def build_config(args: argparse.Namespace, env: dict | None = None) -> Config:
    """Resolve CLI args against GITHUB_* environment fallbacks.

    ``env`` defaults to ``os.environ`` but is injectable so tests need not mutate
    the process.
    """
    if env is None:
        env = os.environ

    artifacts_dir = Path(args.artifacts_dir)
    step_summary = env.get("GITHUB_STEP_SUMMARY")

    return Config(
        artifacts_dir=artifacts_dir,
        # Summary and report land in the artifacts dir, next to the runs they describe.
        summary_file=artifacts_dir / "test-failure-summary.md",
        report_file=artifacts_dir / "test-failure-report.md",
        server_url=env.get("GITHUB_SERVER_URL") or DEFAULT_SERVER_URL,
        repository=env.get("GITHUB_REPOSITORY") or DEFAULT_REPOSITORY,
        max_urls=args.max_urls,
        verbose=args.verbose,
        # In GitHub Actions the summary is also appended to the live job summary.
        step_summary_file=Path(step_summary) if step_summary else None,
        workflow=args.workflow,
        limit=args.limit,
        current_run_id=env.get("GITHUB_RUN_ID"),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workflow",
        default=None,
        help="Workflow name or filename whose runs to download, e.g. "
        '"Run Tests (Linux) [on schedule]" (required).',
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=14,
        help="Number of completed runs to download (default: 14)",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts",
        help="Directory for run-*/junit-*/*.xml, both written and scanned "
        "(default: ./artifacts)",
    )
    parser.add_argument(
        "--max-urls",
        type=int,
        default=3,
        help="Max run URLs listed per test in the report (default: 3)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Log parse progress / skipped files to stderr",
    )
    return parser.parse_args(argv)


# --------------------------------------------------------------------------- #
# Downloading artifacts via the GitHub CLI (`gh`).                             #
# --------------------------------------------------------------------------- #


def build_gh_args(cmd: list[str], repository: str) -> list[str]:
    """Build a ``gh`` argument list, adding ``--repo`` only when known.

    When ``repository`` is empty, ``gh`` infers it from the current checkout.
    """
    args = ["gh", *cmd]
    if repository:
        args += ["--repo", repository]
    return args


def merge_run_ids(fetched: list[str], current_run_id: str | None) -> list[str]:
    """Append the current run id (if set and not already present)."""
    run_ids = list(fetched)
    if current_run_id and current_run_id not in run_ids:
        run_ids.append(current_run_id)
    return run_ids


def run_gh(cmd: list[str], repository: str, capture: bool = False):
    """Run a ``gh`` subcommand, raising ``CalledProcessError`` on failure."""
    args = build_gh_args(cmd, repository)
    # nosec B603,B607 -- fixed argv, no shell; "gh" is resolved from PATH.
    return subprocess.run(args, check=True, text=True, capture_output=capture)


def list_completed_run_ids(workflow: str, limit: int, repository: str) -> list[str]:
    """Return the database ids of the last ``limit`` completed workflow runs."""
    result = run_gh(
        [
            "run", "list",
            "--workflow", workflow,
            "--status", "completed",
            "--limit", str(limit),
            "--json", "databaseId",
            "--jq", ".[].databaseId",
        ],
        repository=repository,
        capture=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def download_run_artifacts(
    run_id: str, artifacts_dir: Path, repository: str
) -> None:
    """Download one run's artifacts into ``<artifacts_dir>/run-<run_id>``."""
    dest = artifacts_dir / f"run-{run_id}"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        run_gh(["run", "download", run_id, "--dir", str(dest)], repository=repository)
    except subprocess.CalledProcessError:
        print(f"No artifacts found for run {run_id}", file=sys.stderr)  # not an error


def run_already_downloaded(artifacts_dir: Path, run_id: str) -> bool:
    """True if ``run-<run_id>`` already holds downloaded artifacts."""
    dest = artifacts_dir / f"run-{run_id}"
    return dest.is_dir() and any(dest.iterdir())


def download_artifacts(cfg: Config) -> None:
    """Download the last N completed runs plus the current run, skipping any
    already on disk. A ``gh run list`` failure propagates (bad auth/workflow); a
    missing artifact for a single run is skipped.
    """
    run_ids = merge_run_ids(
        list_completed_run_ids(cfg.workflow, cfg.limit, cfg.repository),
        cfg.current_run_id,
    )
    print(
        f"Downloading artifacts from up to {len(run_ids)} run(s) into {cfg.artifacts_dir}",
        file=sys.stderr,
    )
    for run_id in run_ids:
        if run_already_downloaded(cfg.artifacts_dir, run_id):
            if cfg.verbose:
                print(f"run {run_id}: already downloaded, skipping", file=sys.stderr)
            continue
        if cfg.verbose:
            print(f"Downloading artifacts from run {run_id}", file=sys.stderr)
        download_run_artifacts(run_id, cfg.artifacts_dir, cfg.repository)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = build_config(args)

    if not cfg.workflow:
        print("error: --workflow is required", file=sys.stderr)
        return 2

    download_artifacts(cfg)

    reports = aggregate(iter_all_failures(cfg.artifacts_dir, verbose=cfg.verbose))

    race_total = summary_race_total(reports)
    genuine = merge_genuine_by_identity(reports)
    summary = render_step_summary(race_total, genuine)
    report = render_detail_report(reports, cfg.server_url, cfg.repository, cfg.max_urls)

    cfg.summary_file.parent.mkdir(parents=True, exist_ok=True)
    with cfg.summary_file.open("w", encoding="utf-8") as fp:
        fp.write(summary)
        if not summary.endswith("\n"):
            fp.write("\n")

    cfg.report_file.parent.mkdir(parents=True, exist_ok=True)
    with cfg.report_file.open("w", encoding="utf-8") as fp:
        fp.write(report)
        if not report.endswith("\n"):
            fp.write("\n")

    # In GitHub Actions, also append the summary to the live job summary.
    if cfg.step_summary_file and cfg.step_summary_file != cfg.summary_file:
        with cfg.step_summary_file.open("a", encoding="utf-8") as fp:
            fp.write("\n")
            fp.write(summary)

    print(summary)

    print(
        f"Analysis complete: {race_total} race FAIL occurrence(s), "
        f"{len(genuine)} distinct genuine failure(s). "
        f"Summary -> {cfg.summary_file}; report -> {cfg.report_file}.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
