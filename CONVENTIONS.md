# Conventions

This file gives conventions for Pelican's code and documentation. Neither pre-commit nor CI checks them. [`CONTRIBUTING.md`](CONTRIBUTING.md) describes the checks that pre-commit and CI run.

## License Header

Start each new code file with this license header, with the current year in place of `{YEAR}`:

```
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

A code file is one written in a programming language, such as Go, TypeScript, Python, or shell. The header is optional in other files.

In a language whose comments do not use `/*` and `*/`, write the header's text with that language's comment marker, as `.github/scripts/go-test/build_tag_packages.sh` does. Put the header after any line that must precede it, such as a shebang or a `//go:build` line.

## Configuration

Read and change configuration through the typed parameters in the `param` package, such as with `param.Server_WebPort.GetInt()` and `param.Server_WebPort.Set(8444)`. Their getters read a cached copy of the configuration. A change made directly through `viper` does not update that copy.

Call `viper` directly only where `param` does not suffice, such as in code that:

- implements the `param` and `config` packages
- binds Cobra flags in `cmd/` with `viper.BindPFlag`
- prints or compares the raw state of `viper`, as `cmd/config_printer/` does
- generates the `param` package, as `generate/` does
- uses its own instance from `viper.New()`, as `web_ui/ui.go` does to update the web configuration file
- loads configuration from YAML for a test, as `fed_test_utils/fed.go` does

Some existing code calls `viper` where `param` would suffice. Do not copy it.

To add a configuration parameter, define it and any default in `docs/parameters.yaml`. The comment at the top of that file lists the defaults that must stay in Go code.

## Web UI

Put code that only one area of the web UI uses in that area's directory. For example, `web_ui/frontend/app/director/components/` holds components that only the director's pages use. Put code that several areas share in a top-level directory of `web_ui/frontend/`, such as `components/`, `helpers/`, or `hooks/`.

Write components as functions, and style them with MUI. Use a specific type or `unknown` instead of `any`.

## Pelican URLs

Do not treat the `pelican://`, `osdf://`, and `stash://` schemes as transfer protocols. A URL with one of these schemes names an object or a collection in a federation. Pelican transfers objects over HTTP. The `pelican_url` package parses these URLs.

## HTTP API

`swagger/pelican-swagger.yaml` documents the HTTP API in [OpenAPI 2.0](https://swagger.io/specification/v2/). No code annotations or generator produce it. When a change affects the HTTP API, update the file in the same change. Follow these conventions in it:

- Give each operation a tag from the file's top-level `tags:` list. To use a new tag, add it to that list.
- State the authorization that each operation requires.
- Define the shapes of requests and responses under `definitions:`, and refer to them with `$ref`. Reuse a matching shape instead of adding a near-duplicate.
- Say when an operation's behavior depends on the kind of caller, such as a system administrator, an owner, or the bearer of a token that names no user.
