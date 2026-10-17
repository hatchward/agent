# syntax=docker/dockerfile:1
#
# hatchward agent sandbox — base layer. → ghcr.io/hatchward/agent:base
#
# One container per agent run, for any code base. Deliberately minimal: git,
# gh, the egress firewall, a non-root "agent" user, and mise so the agent can
# install whatever toolchain the repository needs in user space. No sudo and no
# setuid path to root: root inside a NET_ADMIN container could flush the
# firewall, so the agent never gets it. System packages the agent would want at
# runtime are an image-rebuild request, not a runtime privilege.
#
# CLI layers extend this image (claude/, later codex/): each adds
# its CLI, an allow-domains.d file, and a CMD script built on lib/prompt.sh.
#
# Contract, launch flags and the threat model: README.md and docs/design.md.

# debian:trixie-slim, multi-arch manifest-list digest
# (`docker buildx imagetools inspect debian:trixie-slim`). Bump deliberately;
# Dependabot's docker ecosystem proposes the bumps.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

ARG TARGETARCH
ARG AGENT_UID=1000

# Tools the entrypoint and firewall need, git (+lfs), and the build libraries
# mise needs to compile Ruby (Python and Node come precompiled). gh from
# GitHub's apt repository, keyring pinned by fingerprint.
RUN --mount=type=cache,target=/var/cache/apt,id=apt-cache-$TARGETARCH,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,id=apt-lib-$TARGETARCH,sharing=locked \
    apt-get update -qq && \
    apt-get install --no-install-recommends --no-install-suggests -y \
      ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /etc/apt/keyrings/githubcli-archive-keyring.gpg && \
    gpg --show-keys --with-colons /etc/apt/keyrings/githubcli-archive-keyring.gpg \
      | grep -q '^fpr:::::::::2C6106201985B60E6C7AC87323F3D4EA75716059:$' && \
    echo "deb [signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list && \
    apt-get update -qq && \
    apt-get install --no-install-recommends --no-install-suggests -y \
      git git-lfs gh jq procps tini iptables iproute2 openssl unzip \
      python3 fuse2fs e2fsprogs fuse3 util-linux \
      build-essential pkg-config \
      libssl-dev zlib1g-dev libffi-dev libyaml-dev libreadline-dev libgmp-dev \
      libpq-dev libsqlite3-dev && \
    apt-get purge -y gnupg && apt-get autoremove -y --purge && \
    ! command -v sudo

# Non-root user that owns the workspace and runs the agent. The uid is a
# contract (the runner stages secrets readable by it), hence explicit.
RUN useradd --uid "$AGENT_UID" --user-group --create-home --shell /bin/bash agent && \
    mkdir -p /workspace /run/hatchward /etc/hatchward/allow-domains.d /etc/hatchward/allow-ranges.d /usr/local/lib/hatchward && \
    chown agent:agent /workspace

# mise, for user-space toolchains. Pinned release tarball, checksum verified
# per architecture; bump all three lines together from the release's
# SHASUMS256.txt asset (github.com/jdx/mise/releases).
ARG MISE_VERSION=v2026.9.1
ARG MISE_SHA256_ARM64=98d2ea7b82dd966afdb8a9f4e9edbca771acf2a30d2842bfc0efdb7b61c886a3
ARG MISE_SHA256_AMD64=063dda9149ab6be53da877c2d176afe0eac68e64cf8ca295bd0528720701c65d
RUN case "$TARGETARCH" in \
      amd64) arch=x64; sum="$MISE_SHA256_AMD64" ;; \
      arm64) arch=arm64; sum="$MISE_SHA256_ARM64" ;; \
      *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-linux-${arch}.tar.gz" \
      -o /tmp/mise.tar.gz && \
    echo "$sum  /tmp/mise.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/mise.tar.gz -C /tmp && \
    install -m 0755 /tmp/mise/bin/mise /usr/local/bin/mise && \
    rm -rf /tmp/mise /tmp/mise.tar.gz

# mise: trust the workspace's own config, never prompt, stay quiet. Shims on
# PATH is the only activation that works for a non-interactive exec.
# AGENT_SANDBOXED=1 is part of the contract: a repository's hooks can key on it
# to know they run inside this sandbox (README, "Contract").
ENV MISE_TRUSTED_CONFIG_PATHS=/workspace \
    MISE_YES=1 \
    MISE_QUIET=1 \
    AGENT_SANDBOXED=1 \
    PATH=/home/agent/.local/share/mise/shims:/home/agent/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY --chmod=755 init-firewall.sh /usr/local/bin/init-firewall
COPY --chmod=755 agent-entrypoint.sh /usr/local/bin/agent-entrypoint
COPY --chmod=755 firewall-refresh.sh /usr/local/bin/agent-firewall-refresh
COPY --chmod=755 egress-check.sh /usr/local/bin/agent-egress-check
COPY --chmod=644 lib/prompt.sh /usr/local/lib/hatchward/prompt.sh
COPY --chmod=644 lib/firewall.sh /usr/local/lib/hatchward/firewall.sh
COPY --chmod=644 allow-domains.d/base /etc/hatchward/allow-domains.d/base
COPY --chmod=644 allow-ranges.d/github /etc/hatchward/allow-ranges.d/github

COPY --chmod=644 runtime/*.py /usr/local/lib/hatchward/runtime/
COPY --chmod=755 runtime/bootstrap.sh /usr/local/bin/hatchward-bootstrap
COPY --chmod=755 runtime/fuse2fs.sh /usr/local/bin/hatchward-fuse2fs
COPY --chmod=755 runtime/channel.sh /usr/local/bin/hatchward-channel
COPY --chmod=755 runtime/import.sh /usr/local/bin/hatchward-import
COPY --chmod=755 runtime/configure.sh /usr/local/bin/hatchward-configure
COPY --chmod=755 runtime/run.sh /usr/local/bin/hatchward-run
RUN useradd --uid 10002 --user-group --no-create-home --shell /usr/sbin/nologin hatchward-bridge && \
    mkdir -p /hatchward-backing /hatchward-bounded && chmod 0700 /hatchward-backing && \
    chmod 0755 /usr/local/lib/hatchward/runtime

# contract=3 adds portable execution; the standard entrypoint is preserved.
# See docs/portable-runtime.md for the explicit portable launch contract.
LABEL org.hatchward.agent.contract="3" \
      org.opencontainers.image.source="https://github.com/hatchward/agent"

WORKDIR /workspace
ENTRYPOINT ["tini", "--", "agent-entrypoint"]
CMD ["bash"]
