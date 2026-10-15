# syntax=docker/dockerfile:1
#
# hatchward agent sandbox — Claude Code layer. → ghcr.io/hatchward/agent:claude
#
# Adds the Claude Code CLI to the base image and a CMD that runs one headless
# session. Everything else — firewall, workspace provisioning, privilege drop,
# secret staging — is the base image's; see README.md.
#
# BASE_IMAGE defaults to the tag the README's local build recipe produces, so
# `docker build` after building the base needs no arguments. CI passes the tag
# it just built; the publish job passes the published base by digest. Image
# versions are release tags (base-vX.Y.Z, claude-vX.Y.Z) applied by the
# publish job, never edits here.

ARG BASE_IMAGE=agent:base
FROM ${BASE_IMAGE}

# Claude Code release. The installer verifies the download against the
# published manifest checksum; auto-update is off, so this pin is the only way
# the CLI version changes. Bump deliberately.
ARG CLAUDE_VERSION=2.1.236

# AGENT_STAGE_VARS names the credential variables the base entrypoint stages
# as files (a list of names, not values).
ENV DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    CLAUDE_PROJECT_DIR=/workspace \
    AGENT_STAGE_VARS="GH_TOKEN ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN"

USER agent
RUN curl -fsSL https://claude.ai/install.sh | bash -s -- "${CLAUDE_VERSION}" && \
    /home/agent/.local/bin/claude --version | grep -F "${CLAUDE_VERSION}"
USER root

COPY --chmod=644 claude/allow-domains.d/claude /etc/hatchward/allow-domains.d/claude
COPY --chmod=755 claude/agent-claude.sh /usr/local/bin/agent-claude

CMD ["agent-claude"]
