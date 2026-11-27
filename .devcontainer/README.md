# Pelican Development Container

This directory configures a development container for Pelican. The container holds the tools to build, test, and run Pelican, and it runs in GitHub Codespaces or locally in VS Code. [`CONTRIBUTING.md`](../CONTRIBUTING.md) explains how to use those tools.

## Opening the Container

### GitHub Codespaces

1. On GitHub, go to the [Pelican repository](https://github.com/PelicanPlatform/pelican) or your fork.
1. Click **Code**, and select the **Codespaces** tab.
1. Click **Create codespace on main**, or create a codespace on your branch.
1. Wait for the container to build and start.

### VS Code

1. Install [Docker](https://docs.docker.com/get-docker/) and [VS Code](https://code.visualstudio.com/), and start Docker.
1. In VS Code, install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers).
1. Open your clone of the repository in VS Code.
1. Click **Reopen in Container** when VS Code offers it. Otherwise, click the button in the lower-left corner of the status bar, and select **Reopen in Container** from the menu that opens.

The first start downloads the container image, which can take several minutes. The container mounts your clone at `/workspaces/<name>`, where `<name>` is the name of the clone's directory, so a change on either side appears on the other.

Once the container starts, the lower-left corner of the status bar shows **Dev Container: Pelican**. VS Code's terminals then run inside the container, not on your machine.

## Container Details

The container runs the image `hub.osg-htc.org/pelican-ci/pelican-dev:latest-itb`, which CI builds from the `pelican-dev` stage of [`images/Dockerfile`](../images/Dockerfile) on each push to `main`. The image includes Go, Node.js, pnpm, GoReleaser, XRootD, pre-commit, and Delve. `devcontainer.json` adds VS Code's extensions for Go, Makefiles, and YAML.

### Users

The container runs as the user `vscode`, who is not root and can use `sudo` without a password. Tools that refuse to run as root therefore work in the container. One example is Claude Code with `--dangerously-skip-permissions`.

The image also has users for testing, such as `alice`. Use them to test multi-user origins or the dropping of privileges. To switch to `alice`, run `sudo -iu alice`.

### Configuration

When it runs as `vscode`, Pelican reads its configuration from `~/.config/pelican/pelican.yaml`. When that file does not exist, Pelican reads `/etc/pelican/pelican.yaml`, which the image provides. That file sets `TLSSkipVerify: true`, so that the client accepts the self-signed certificates of servers in the container.

### Ports

`devcontainer.json` forwards these ports from the container to your machine:

- 8444: Default Pelican server port
- 8443: Pelican web UI port
- 8080: Additional service port
