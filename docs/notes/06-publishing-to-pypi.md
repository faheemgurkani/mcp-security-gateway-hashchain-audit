# 06 — Publishing to PyPI: a first release, step by step

Written 2026-11-14 for the owner's learning, alongside the first PyPI release of this
project as **`mcp-gateway-lab`**. Each section explains one idea, then says what we did
here and why. Decision: D-025.

## Contents

1. [Is it a good idea?](#1-is-it-a-good-idea)
2. [What PyPI, a wheel and an sdist are](#2-what-pypi-a-wheel-and-an-sdist-are)
3. [Choosing a name: the distribution name and the import name](#3-choosing-a-name-the-distribution-name-and-the-import-name)
4. [Package metadata: what each pyproject field does](#4-package-metadata-what-each-pyproject-field-does)
5. [Versions: semantic versioning, and why a release is permanent](#5-versions-semantic-versioning-and-why-a-release-is-permanent)
6. [What goes into the packages, and how to audit them](#6-what-goes-into-the-packages-and-how-to-audit-them)
7. [TestPyPI before PyPI](#7-testpypi-before-pypi)
8. [Trusted Publishing instead of API tokens](#8-trusted-publishing-instead-of-api-tokens)
9. [The release workflow](#9-the-release-workflow)
10. [One-time setup (owner)](#10-one-time-setup-owner)
11. [The release checklist (every time)](#11-the-release-checklist-every-time)
12. [What went wrong on the way](#12-what-went-wrong-on-the-way)

## 1. Is it a good idea?

Yes, for this project:

- **Lower barrier.** `pipx install mcp-gateway-lab` instead of a git URL. Most people
  will not install a security tool from a URL they have to copy.
- **Citable versions.** A paper or the CITATION.cff can point to "mcp-gateway-lab 0.3.0",
  which never changes.
- **Pinnable.** Other projects' CI (including the GitHub Action) can pin a version, so an
  update on `main` can't break them.

The cost is responsibility: a published version is public and **permanent**, and people
may depend on it. That is why the steps below put checks in front of every upload.

When it would *not* be a good idea: code that is only useful inside its own repo (like the
Docker lab), or names you can't keep maintaining.

## 2. What PyPI, a wheel and an sdist are

- **PyPI** (pypi.org) is the public index `pip`, `uv` and `pipx` install from.
- A **wheel** (`.whl`) is a ready-to-install zip: the Python files plus metadata. Installing
  it is just unzipping into `site-packages` and creating the commands (`mcp-lab`).
- An **sdist** (`.tar.gz`, "source distribution") is the source needed to *build* the wheel.
  Tools fall back to it when no wheel fits, and distributions (Debian, conda) build from it.
- A **build backend** turns the repo into both files. Ours is **hatchling** (set in
  `[build-system]`); `uv build` runs it and writes `dist/`.

Our wheel is "pure Python" (`py3-none-any`): one file works on every OS.

## 3. Choosing a name: the distribution name and the import name

A package has **two** names, and both must be safe:

| Name | Ours | Where it must be unique |
|---|---|---|
| distribution name (what you `pip install`) | `mcp-gateway-lab` | on PyPI: first come, first served |
| import name (what you `import`) | `mcp_lab` | in everyone's `site-packages` |

PyPI only checks the first. **Nothing checks the second.** If two packages install the
same top-level module, the last one installed silently overwrites the other.

**What we found:** an unrelated package, `mcp-gateway` 1.2.1, already installs a top-level
`mcp_gateway` module, the import name our reference gateway used. So before publishing we
moved it to `mcp_lab.gateway` (and its command `mcp-gateway` to `mcp-lab-gateway`). Now
the project ships exactly one top-level package, `mcp_lab`, under a name that is clearly
ours. This broke the old import path, which is why the version became 0.3.0 (section 5).

How to check a name: `https://pypi.org/pypi/<name>/json` returns 404 if it is free. For
the import name, download the wheels of similarly named packages and look at their
top-level folders (`unzip -l x.whl`).

We chose `mcp-gateway-lab` over the shorter `mcp-lab` because it says what the package is,
and doesn't look like an official Model Context Protocol tool.

## 4. Package metadata: what each pyproject field does

Everything PyPI shows comes from `[project]` in `pyproject.toml`:

| Field | What it does |
|---|---|
| `name` | the distribution name |
| `dynamic = ["version"]` + `[tool.hatch.version]` | the version is read from `src/mcp_lab/__init__.py`, so it is defined **once** (`mcp-lab version` prints the same string) |
| `description`, `readme` | the one-liner and the long page on PyPI. The README is rendered there, so **relative links break**: ours are now absolute GitHub URLs |
| `license` | an SPDX identifier (`MIT`); the `LICENSE` file is bundled automatically |
| `authors` | name and email shown on the page |
| `requires-python` | pip refuses to install on older Pythons |
| `dependencies` | installed automatically; use ranges (`mcp>=2.3,<3`), never exact pins, so you don't block users' other packages |
| `optional-dependencies` | extras: `pip install "mcp-gateway-lab[external]"` |
| `classifiers` | search filters on PyPI (Python versions, topic, maturity: "3 - Alpha") |
| `[project.urls]` | the links in PyPI's sidebar (homepage, docs, issues, changelog) |
| `[project.scripts]` | the commands created on install: `mcp-lab`, `mcp-lab-gateway` |

`[dependency-groups] dev` (pytest, ruff) is **not** published: it is only for working on
the repo.

## 5. Versions: semantic versioning, and why a release is permanent

**Semantic versioning** (`MAJOR.MINOR.PATCH`):

- PATCH (0.3.**1**): bug fixes only;
- MINOR (0.**4**.0): new features;
- MAJOR (**1**.0.0): breaking changes.

Before 1.0 the convention is looser: a MINOR bump may break things. Our rename broke the
import path, so 0.2.0 → **0.3.0**.

**A version on PyPI is permanent.** You can *yank* a release (pip then skips it unless
asked for it by exact version) or delete it, but you can **never upload the same version
number again**, even after deleting it. A mistake is fixed with a new version (0.3.1),
not by replacing 0.3.0. That is the main reason for TestPyPI and the checks in section 9.

`CHANGELOG.md` records what changed in each version, in the
[Keep a Changelog](https://keepachangelog.com) format.

## 6. What goes into the packages, and how to audit them

**The near miss.** Hatchling decides what goes into the sdist from `.gitignore`. Our
personal `docs/TODO.md` is ignored through `.git/info/exclude` instead, a local-only
ignore file that hatchling does **not** read. A default sdist would have published the
private TODO list to PyPI, permanently.

What we did:

- **An allow-list, not a deny-list.** `[tool.hatch.build.targets.sdist] include = [...]`
  names exactly what ships: `src`, `tests`, `examples`, README, LICENSE, CHANGELOG,
  CITATION.cff. Anything new is left out until someone adds it on purpose.
- **An audit script**, `scripts/check_dist.py`. It opens every built file and fails if it
  finds:
  - a forbidden file: CLAUDE.md, TODO.md, `.env`, keys, anything under `lab/`, the
    embargoed adapter;
  - an unexpected top-level entry.

  It runs in CI on every push and in the release workflow. It was tested by planting a
  `docs/TODO.md` in a fake sdist, which it caught.
- **Look before you publish.** `tar tzf dist/*.tar.gz` and `unzip -l dist/*.whl` list the
  contents. Ours: the wheel has 35 files (only `mcp_lab/`), the sdist 55.

Also checked: the built files contain no embargoed gateway names.

What is deliberately **not** in the wheel: the Docker lab (`lab/`), the docs and the
results. They only make sense in the repo; the wheel is the tool.

## 7. TestPyPI before PyPI

**TestPyPI** (test.pypi.org) is a separate copy of PyPI for practice. It has separate
accounts and is wiped from time to time. Uploading there first shows how the page renders,
proves the upload works, and lets you install the real artifact, all without spending a
permanent version number on PyPI.

Our release workflow always goes to TestPyPI first, installs from it, runs `mcp-lab`, and
only then publishes to PyPI.

## 8. Trusted Publishing instead of API tokens

The old way: create an API token on PyPI and store it as a GitHub secret. A leaked token
lets anyone upload malicious versions of your package.

**Trusted Publishing** (OpenID Connect) needs no stored secret:

1. On PyPI you declare: "uploads for `mcp-gateway-lab` may come from GitHub repo
   `faheemgurkani/mcp-security-gateway-hashchain-audit`, workflow `release.yml`,
   environment `pypi`".
2. When that workflow runs, GitHub gives it a short-lived signed identity token
   (`permissions: id-token: write`).
3. PyPI checks the signature and the repo, workflow and environment, then accepts the
   upload. The credential expires within minutes.

Combined with a GitHub **environment** that requires your approval, nobody, not even a
compromised workflow, can publish without your click. PyPI also attaches **attestations**
(signed provenance) to each file, so users can verify where it was built.

Because the project doesn't exist on PyPI yet, you register a **pending publisher**. It
becomes a normal trusted publisher on the first upload, which also reserves the name.

## 9. The release workflow

`.github/workflows/release.yml` runs when a tag like `v0.3.0` is pushed:

| Job | What it does |
|---|---|
| `build` | checks the tag matches `__version__`; lint and tests; `uv build`; the content audit; `twine check --strict` (validates metadata and that the README renders) |
| `testpypi` | uploads to TestPyPI (environment `testpypi`) |
| `check-testpypi` | installs `mcp-gateway-lab==<version>` from TestPyPI into a fresh venv and scores the toy gateway |
| `pypi` | uploads the **same files** to PyPI (environment `pypi`, waits for your approval) |

The same files that were built and tested once are what reach PyPI; nothing is rebuilt
between steps.

## 10. One-time setup (owner)

*(Filled in as it is done.)*

## 11. The release checklist (every time)

1. Update `__version__` in `src/mcp_lab/__init__.py`, plus `version` and `date-released`
   in `CITATION.cff`, and the BibTeX version in the README.
2. Move the "unreleased" heading in `CHANGELOG.md` to the version and date.
3. Locally: `uv run pytest`, `uv build`, `uv run python scripts/check_dist.py dist`, and
   `uvx twine check --strict dist/*`.
4. Commit and push; wait for CI to go green.
5. `git tag v<version> && git push origin v<version>`.
6. Watch the Release workflow. After `check-testpypi` passes, approve the `pypi` job.
7. In a fresh environment, run `pipx install mcp-gateway-lab==<version>` and then
   `mcp-lab version`.
8. Create a GitHub release from the tag, with the changelog section as notes.

## 12. What went wrong on the way

- **Import-name clash** with the unrelated `mcp-gateway` package (section 3). Found by
  checking the name, then downloading that package's wheel. Fixed by moving to
  `mcp_lab.gateway`.
- **The sdist would have leaked `docs/TODO.md`** (section 6). Fixed with an allow-list and
  an audit script.
- **README links would have been broken on PyPI.** Fixed by making them absolute.
- **A test Docker run overwrote a committed result file** (`lab/results/colocated.json`)
  with a partial run. Caught in `git status` and restored. Lesson: partial runs
  (`--only`) write to the same file as full runs.
