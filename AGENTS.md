# Instructions for AI Agents

These instructions apply to AI agents that work in Pelican's repository. The repository holds a Go module and a web UI, which is in `web_ui/frontend/`. `go.mod` and `web_ui/frontend/package.json` list their dependencies and the dependencies' versions.

[`CONTRIBUTING.md`](CONTRIBUTING.md) explains how to build Pelican, run a federation in a box to try a change by hand, regenerate generated files, run the tests and checks, and open a pull request. It also gives guidelines for scoping a change. Read it before starting a task. This file adds rules for agents to those in `CONTRIBUTING.md`.

## Conventions

### Go

Start each new Go file with this license header, with the current year in place of `{YEAR}`:

```go
/***************************************************************
 *
 * Copyright (C) {YEAR}, Pelican Project, Morgridge Institute for Research
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
```

In new code, read configuration through the typed parameters in the `param` package, such as `param.Server_WebPort.GetInt()`. Change it with a parameter's `Set` method or with `param.Set`, not through `viper`. The getters read a cached copy of the configuration, which these functions update. A change made directly through `viper` does not reach that copy until something rebuilds it, such as a call to `param.Refresh()`.

Call `viper` directly only in these places:

- The `param` and `config` packages.
- `cmd/`, to bind Cobra flags with `viper.BindPFlag`.
- `generate/`, which generates the `param` package.
- `cmd/config_printer/`, which prints and compares the raw state of `viper`.
- Code that reads or writes a file other than Pelican's configuration through its own `viper.New()` instance, as `web_ui/ui.go` does for the web configuration file.

Some existing code outside these places calls `viper` directly. Do not copy it.

To add a configuration parameter, define it and its default in `docs/parameters.yaml`. The comment at the top of that file lists the defaults that must stay in Go code.

### Web UI

Put React components in `web_ui/frontend/components/`, pages and routes in `web_ui/frontend/app/`, helper functions in `web_ui/frontend/helpers/`, and hooks in `web_ui/frontend/hooks/`. Write components as functions, and style them with MUI. Prefer explicit types to `any`.

### Pelican URLs

In code and documentation, treat the `pelican://`, `osdf://`, and `stash://` schemes as ways to discover a federation, not as transfer protocols. Pelican transfers objects over HTTP. The `pelican_url` package parses these URLs.

## Documentation

`docs/` holds most of Pelican's documentation. `docs/app/` holds the source of the user documentation at https://docs.pelicanplatform.org/.

Contributors write most of the documentation by hand. Generators produce the rest, such as the CLI reference in `docs/app/commands-reference/`. No check confirms that the hand-written documentation matches the code, so it can be wrong or incomplete. Confirm what it says against the code before relying on it. When a change makes it wrong or incomplete, update it in the same change.

### HTTP API

`swagger/pelican-swagger.yaml` documents the HTTP API in OpenAPI 2.0. No code annotations or generator produce it. When a change adds or removes an operation, or changes an operation's behavior or the shapes of its requests and responses, update the file in the same change. Follow these conventions in it:

- Give each operation a tag from the file's top-level `tags:` list. To use a new tag, add it to that list.
- State the authorization that an operation requires in its description, with one of the file's inline labels: `` `Authentication Required` ``, `` `Admin privilege Required` ``, or `` `User Admin Required` ``. OpenAPI 2.0 has no scheme for cookie authentication, so these labels are the contract.
- Define the shapes of requests and responses under `definitions:`, and refer to them with `$ref`. Reuse an existing shape where its contract matches. Do not add a near-duplicate.
- Describe security-relevant behavior accurately. Say so when an operation's behavior depends on the kind of caller, such as a system administrator, an owner, or the bearer of an anonymous token.

### Markdown

The `mdformat` pre-commit hook formats `.md` files, but not the `.mdx` pages in `docs/app/`. In those pages, follow the line breaks of the page being edited.

## Generated Files

Edit the inputs of generated files, not the generated files. The [Generated Files](CONTRIBUTING.md#generated-files) section of `CONTRIBUTING.md` explains how to recognize generated files. The code of each generator shows which files it reads and writes. The generator in `generate/` reads YAML files such as `docs/parameters.yaml`. The `//go:generate` directives in `cmd/main.go` write the CLI reference in `docs/app/commands-reference/` from the Cobra commands.

After a change to an input, run the commands in that section. Include the regenerated files in the change.

## Building

To build Pelican, follow the [Building](CONTRIBUTING.md#building) section of `CONTRIBUTING.md`. After a build, check `git status`. Report any change to `go.mod`, `go.sum`, or generated files that the task did not call for.

The web UI uses pnpm, not npm. To install its dependencies, run `pnpm install --frozen-lockfile` in `web_ui/frontend/`. That command fails rather than change `pnpm-lock.yaml`. Change the lockfile only when the task changes the web UI's dependencies.

## Testing

The [Testing](CONTRIBUTING.md#testing) section of `CONTRIBUTING.md` explains how to run the tests and gives the rules for writing them. Follow those rules.

### Running Go Tests

Before attributing a test failure to a change, check that the tools that the test needs are installed. `CONTRIBUTING.md` names the tools whose absence makes tests fail rather than skip. If one is missing, report it. Do not change code or tests to work around it.

### Writing Go Tests

To apply the criterion for `test_utils.SkipIfShort` that concerns a test's time, take the time from the JUnit artifacts of CI runs. Do not estimate it from the test's code. The test workflows upload the artifact `junit-pelican-<os>`, such as `junit-pelican-Linux`. On Linux and macOS, they also upload `junit-pelican-server-<os>`. Download one with `gh run download <run-id> --name <artifact>`. Use runs that test the full suite, such as those for pushes to `main`. Pull request runs skip the tests that already call `SkipIfShort`.

### Running Web UI Tests

After a change to the web UI, run its Jest tests with `pnpm test` in `web_ui/frontend/`. No CI workflow runs them. CI runs the Playwright tests in `web_ui/frontend/e2e/`, and `.github/workflows/test-webui-e2e.yml` shows which ones. Run them only when the task calls for it, as `web_ui/frontend/e2e/README.md` describes.

## Checks

Before finishing a change, run each check in the [Checks](CONTRIBUTING.md#checks) section of `CONTRIBUTING.md` that applies to it:

- Run `pre-commit run --files` on the changed files. Review the fixes that the hooks make.
- After a change to Go code, lint it with `golangci-lint run` once for each `GOOS` that CI uses. `pre-commit run --files` skips the hooks for golangci-lint, which run only in the `pre-push` and `manual` stages. `.golangci.yaml` sets both build tags, so these commands cover all of the `cmd` package. Use the version of golangci-lint that CI uses.
- After a change to the web UI or to `docs/parameters.yaml`, run the check for it.
