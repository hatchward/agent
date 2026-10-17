# riprap skill answers

## riprap:release

- Release branch: `main`
- Tag shape: `v` + semantic, e.g. `v0.5.0`
- Version files: none — the tag is the version
- Notes: `.github/releases/<tag>.md`, plus a `## [<version>]` entry in `CHANGELOG.md`
- Bump and tag: `bin/release <version>` — it checks the version, the commit, CI, and the notes, then pushes the tag
- Publishes: the `publish` job in `.github/workflows/ci.yml`, on tag push (ghcr.io/hatchward/agent images + GitHub release) — run nothing by hand
