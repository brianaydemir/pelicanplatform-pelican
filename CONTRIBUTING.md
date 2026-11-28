# Contributing to Pelican

Welcome! We are glad that you want to contribute to the Pelican project! 💖

As a newcomer, you are in the best position to tell us where the project needs help: problems you encounter while setting up a development environment, gaps in the documentation, and bugs in our scripts. If anything doesn't make sense, or doesn't work when you run it, please open a [bug report](https://github.com/PelicanPlatform/pelican/issues/new?assignees=&labels=bug&projects=&template=bug_report.md&title=) and let us know!

## Tech Stack

Pelican's servers and client are [Go](https://go.dev/) programs. They use these libraries, among others:

- [Cobra](https://cobra.dev/) for the command line
- [Viper](https://github.com/spf13/viper) for configuration
- [Gin](https://gin-gonic.com/) for HTTP
- [Logrus](https://github.com/sirupsen/logrus) for logging
- [GORM](https://gorm.io/) and [Goose](https://github.com/pressly/goose) for the [SQLite](https://www.sqlite.org/) database and its migrations
- [`github.com/prometheus/client_golang`](https://github.com/prometheus/client_golang) for metrics

The servers also embed a [Prometheus](https://prometheus.io/) server, which collects metrics and answers queries about them.

The servers' web UI uses [TypeScript](https://www.typescriptlang.org/), [React](https://react.dev/), and [Next.js](https://nextjs.org/), among others.

`swagger/pelican-swagger.yaml` documents the HTTP API in [OpenAPI 2.0](https://swagger.io/specification/v2/).

Origins and caches can serve data through [XRootD](https://xrootd.org/), depending on configuration.

## Issues

Use GitHub issues to report problems, to request features, and to discuss a change before opening a pull request. To report a security vulnerability, follow the [security policy](SECURITY.md) instead.

Before opening an issue, search the existing issues and pull requests. If an issue already describes your problem, add your reproduction details to it rather than opening a new one.

Before you start work on an issue, comment on it to say so.

## Development Environment

Fork the [Pelican repository](https://github.com/PelicanPlatform/pelican), and clone your fork.

The recommended environment is Pelican's development container, which holds the tools to build, test, and run Pelican. It runs in GitHub Codespaces or locally in VS Code. [`.devcontainer/README.md`](.devcontainer/README.md) explains how to open it.

To develop without the container, install:

- [Go](https://go.dev/), at the version that `go.mod` requires or later
- [golangci-lint](https://golangci-lint.run/), at the version that `.pre-commit-config.yaml` pins
- [Node.js](https://nodejs.org/) and [pnpm](https://pnpm.io/), at the versions that `web_ui/frontend/package.json` names
- [Python 3](https://www.python.org/)
- [GoReleaser](https://goreleaser.com/)
- [GNU Make](https://www.gnu.org/software/make/)
- [pre-commit](https://pre-commit.com/)
- [XRootD](https://xrootd.org/) and Pelican's XRootD plugins, to run XRootD-based origins and caches, and to run the tests that start a federation. Without them, those tests fail rather than skip.

The development container includes everything in this list except golangci-lint. To run the Go linters in the container, install golangci-lint in it.

Pelican's XRootD plugins, such as [`xrdhttp-pelican`](https://github.com/PelicanPlatform/xrdhttp-pelican) and [`xrdcl-pelican`](https://github.com/PelicanPlatform/xrdcl-pelican), must be at versions that work with the installed XRootD. `images/Dockerfile` shows which packages the container images install, and at which versions. `github_scripts/osx_install.sh` shows how CI builds XRootD and the plugins from source on macOS, including from Pelican's fork of XRootD.

## Building

GoReleaser builds Pelican's binaries. To build them for the local platform, generate GoReleaser's configuration, then build:

```bash
make goreleaser-config
goreleaser build --clean --snapshot --single-target --config .goreleaser.generated.yml
```

GoReleaser writes the binaries to directories under `dist/`. To build only the client or only the servers, add `--id pelican` or `--id pelican-server`.

Before it builds, GoReleaser tidies the Go module, runs `go generate ./...`, and builds the web UI with `make web-build`. A build can therefore change `go.mod`, `go.sum`, and generated files. [`web_ui/frontend/README.md`](web_ui/frontend/README.md) describes how to develop the web UI.

## Running Pelican

Run Pelican's binaries from the root of your clone, after a build for the local platform.

### Client

To check the client, download a test object from the [OSDF](https://osg-htc.org/services/osdf), a public federation:

```bash
dist/pelican_*/pelican object get pelican://osg-htc.org/pelicanplatform/test/hello-world.txt ~/hello-world.txt
cat ~/hello-world.txt
```

The object reads "If you are seeing this message, getting an object from OSDF was successful." The [client documentation](https://docs.pelicanplatform.org/getting-data-with-pelican/client) describes the client's other commands and options.

### Federation in a Box

`pelican-server serve` can run several servers at once. When it runs a director, a registry, an origin, and a cache, they form a federation in a box: a whole federation on one machine.

Run the federation in a box as a user other than root. As root, Pelican runs XRootD as the `xrootd` user, which cannot read the origin's files in root's home directory. VS Code and Codespaces run the development container as `vscode`. A container started directly from its image runs as root, but the image's test users, such as `alice`, are not root.

1. Create a directory for the origin to export, with an object in it:

   ```bash
   mkdir -p ~/fed/data
   echo "Hello from a federation in a box" > ~/fed/data/hello.txt
   ```

1. Create a configuration file for the federation:

   ```bash
   cat > ~/fed/pelican.yaml <<EOF
   TLSSkipVerify: true
   Origin:
     StoragePrefix: $HOME/fed/data
     FederationPrefix: /test
     EnablePublicReads: true
   Registry:
     RequireOriginApproval: false
     RequireCacheApproval: false
   EOF
   ```

   With this configuration, the origin exports `~/fed/data` as the namespace `/test` and lets anyone read it. The registry approves the origin and the cache without an administrator. The servers use self-signed certificates. `TLSSkipVerify` lets the client and the servers accept them.

1. Start the federation:

   ```bash
   dist/pelican-server_*/pelican-server serve --config ~/fed/pelican.yaml --module director,registry,origin,cache
   ```

   As they start, the servers log errors, such as ones about the MaxMind GeoIP database and incomplete registrations. These errors do not stop the federation from serving objects.

1. In another terminal, download the object through the federation:

   ```bash
   dist/pelican_*/pelican object get --config ~/fed/pelican.yaml pelican://localhost:8444/test/hello.txt ~/fed/hello-copy.txt
   cat ~/fed/hello-copy.txt
   ```

   The director redirects the client to the cache, which fetches the object from the origin.

The documentation describes how to configure each server: an [origin](https://docs.pelicanplatform.org/federating-your-data/origin), a [cache](https://docs.pelicanplatform.org/operating-a-federation/cache), a [director](https://docs.pelicanplatform.org/operating-a-federation/director), and a [registry](https://docs.pelicanplatform.org/operating-a-federation/registry).

## Generated Files

Generators produce some files from others. The CLI reference in `docs/app/commands-reference/` comes from the Cobra commands. Every other generated file that Git tracks starts with a `// Code generated` comment. Edit the inputs, not the generated files. After changing an input, run these commands, and commit the files that they change:

```bash
go generate ./...
go generate -tags client ./cmd/...
go generate -tags server ./cmd/...
```

The `cmd` package builds only with the `client` or `server` build tag, so `go generate ./...` alone skips it. In CI, the "Check Go Generate Has Been Run" workflow fails if these commands change any file.

## Testing

### Running Go Tests

Some tests build only with the `client` or `server` build tag, so `go test ./...` skips them. CI tests with each tag separately, because the client's and the servers' builds use one tag each. Code can pass with both tags at once and fail with only one. Before opening a pull request, run the tests with each tag:

```bash
go test -tags client ./...
go test -tags server $(.github/scripts/go-test/build_tag_packages.sh)
```

For pull requests, CI adds `-short`, which skips the tests that call `test_utils.SkipIfShort`.

### Writing Go Tests

- Make each test independent of the others. Write files only under `t.TempDir()`. Reset the global configuration before and after each test that changes it. For example, call `server_utils.ResetTestState()` at the start of the test, and pass it to `t.Cleanup`.
- Do not add a `time.Sleep` call that waits for a condition, because such waits make tests unreliable. Wait for the condition itself, such as with `require.Eventually`.
- By default, let each test run in every CI run. Call `test_utils.SkipIfShort(t, "reason")` as a test's first statement only when one of these holds:
  - The test needs a backend, service, or privilege that the runners for pull requests should not depend on, such as HTCondor, rclone, MinIO, or root.
  - The test's measured time outweighs what it checks. The JUnit artifacts of CI runs give each test's time.

### Running Web UI Tests

To run the web UI's Jest tests, run `pnpm test` in `web_ui/frontend/`. The Playwright tests in `web_ui/frontend/e2e/` run against a running Pelican server. [`web_ui/frontend/e2e/README.md`](web_ui/frontend/e2e/README.md) explains how to run them.

## Checks

Pelican uses pre-commit to check each commit. The hooks for golangci-lint and the web UI's formatter run before each push instead. To install the hooks for commits and pushes, run these commands in your clone:

```bash
pre-commit install
pre-commit install --hook-type pre-push
```

Before opening a pull request, run the checks that apply to your change:

- To lint the Go code, run:

  ```bash
  GOOS=linux golangci-lint run
  GOOS=darwin golangci-lint run --disable=unused
  GOOS=windows golangci-lint run --disable=unused
  ```

  The `darwin` and `windows` runs disable the `unused` linter, because a symbol's only callers can be in files that the build for one platform excludes.

  To fix the formatting problems that golangci-lint reports, run `golangci-lint fmt`.

- To check the web UI's formatting, run:

  ```bash
  pnpm --dir web_ui/frontend run format
  ```

  To fix the formatting, run `pnpm --dir web_ui/frontend run format:fix`.

- To check `docs/parameters.yaml`, run:

  ```bash
  python3 .github/scripts/validate-parameters/main.py
  ```

  The script needs the Python packages in `.github/scripts/validate-parameters/requirements.txt`.

CI runs the commit hooks and each of these checks on every pull request.

## Pull Requests

To decide what belongs in a pull request, use these guidelines and your judgment:

- Address one concern. Avoid changing the formatting or style of code that the concern does not involve. Cleaning up the code around a changed line can be appropriate, but the farther code is from the change, the less likely that is.
- Fix the root cause of a problem, not its symptoms. Consider whether a bug belongs to a class of bugs that one fix can prevent. For example, passing a configuration parameter's name as a string allows a typo in the name. The typed parameters in the `param` package turn such a typo into a compile error.

Each pull request must follow these rules:

- Link the issue that the pull request resolves, so that merging the pull request closes the issue.
- Make each commit a well-defined, well-scoped change.
- Follow the conventions in [`CONVENTIONS.md`](CONVENTIONS.md).
- Add or update tests for the functionality that you fix or change.
- Update the documentation that the change affects. Most of it is in `docs/`.

If no one reviews your pull request within a week, ask a core contributor for a review in a comment on it.

### Pull Requests That Change the Container Images

A change to the packages that `images/Dockerfile` installs in the container images takes two pull requests: one that changes the packages, and one with the changes that depend on them, such as changes to code. CI tests each pull request in the `pelican-test` image from the most recent push to `main`, so a pull request cannot test the packages that it changes.

Before opening the pull requests, test the two changes together on your fork. [`.github/workflows/README.md`](.github/workflows/README.md#forks) explains how to set up a fork to build and test its own images.

## About This Guide

The first version of this guide adapted the [CNCF contributing guideline template](https://github.com/cncf/project-template/blob/main/CONTRIBUTING.md) and the [Auth0 contributing guideline](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md).
