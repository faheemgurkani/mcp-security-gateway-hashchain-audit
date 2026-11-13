# Changelog

All notable changes to the `mcp-gateway-lab` package. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (before 1.0, a minor version may break things).

## [0.3.0] - unreleased

First release on PyPI.

### Changed
- **Breaking:** the reference gateway moved from the top-level `mcp_gateway` package to
  `mcp_lab.gateway`, and its command from `mcp-gateway` to `mcp-lab-gateway`. An
  unrelated PyPI package already installs a top-level `mcp_gateway` module, so keeping
  the old name would have let one overwrite the other.
- README links are absolute, so they work on PyPI.
- The version is defined once, in `mcp_lab/__init__.py`.

### Added
- Package metadata for PyPI: classifiers, author email, a changelog link.
- An explicit allow-list for the source distribution.

## [0.2.0] - 2026-11-12

Installable from GitHub only.

### Added
- `mcp-lab`: one-command scoring from a YAML spec, a generic A12 forger,
  `check-deployment`, `inspect-log`, and a GitHub Action.
- Argument rules from a config file, or from each tool's pinned schema.
- A user guide, a review template, a technical report, a citation file and a contributing
  guide.

## [0.1.0] - 2026-11-09

The test lab: the reference gateway, the Docker lab with three deployment profiles,
attacks A1–A11, the scorecard and the LLM attacker.
