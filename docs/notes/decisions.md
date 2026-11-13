# Decision log

Format per entry: **ID · date · status**, then Context / Options / Decision / Rationale.

---

### D-001 · 2026-11-06 · accepted
**Context:** A weekend-sized AI-security portfolio project that also supports the Apart sprint.
**Options:** the 12-stage list (prompt injection, RAG poisoning, PII proxy, PyRIT CI, and others).
**Decision:** combine Stage 3 (MCP tool security) and Stage 11 (audit and governance) into one MCP security gateway with a hash-chained audit log.
**Rationale:** one end-to-end story (attack, defence, proof); feeds the sprint's Track 4.2; fits a weekend. Stage 2 risks provider terms of service; Stages 9, 10 and 12 take weeks; Stage 8 is a later follow-up aimed at this gateway.

### D-002 · 2026-11-06 · accepted
**Decision:** repo name `mcp-security-gateway-hashchain-audit`; Python `src/` layout, with one package `mcp_gateway` split into `validation/`, `policy/`, `audit/` and `proxy/`.
**Rationale:** the name states the three technical pieces; each subpackage maps to one stage of the pipeline, so each can be tested on its own.

### D-003 · 2026-11-06 · superseded by D-004 (see notes/03 for why)
**Context:** MCP gateways and hash-chained agent loggers both already exist (see notes/02).
**Decision:** position the project as *agent-proof logging*: the recorder sits outside the agent's trust boundary, with an external anchor and a standalone verifier. Ship four deliverables: drop-in stdio proxy, open log format + verifier, attack test suite mapped to OWASP ASI, and threat model write-up. The weekend MVP is the proxy, a basic verifier and a few attack cases.
**Rationale:** it differentiates from in-process audit SDKs; it is directly useful to the Apart Track 4.2 forensics work; the format and test suite are things others can build on.

### D-004 · 2026-11-08 · accepted
**Context:** Independent validation (notes/03) found 15+ gateways with hash-chained logs, existing external anchoring and non-bypass designs, and outside-attacker suites (MCPSEC). There was no benchmark with the agent as the attacker.
**Decision:** the project becomes an **agent-as-attacker test lab**: reference gateway, adapters for existing gateways, scripted attack harness (A1–A11), observer and scorecard. Keep the repo name (owner's choice).
**Rationale:** the only clearly open gap; cites the Tübingen/Snyk trace-tampering result; still teaches Stages 3 and 11 through the reference gateway, and adds Stage 8.

### D-005 · 2026-11-08 · accepted
**Decision:** transport is MCP **Streamable HTTP** from agent to gateway; **stdio** from gateway to tool servers.
**Rationale:** a stdio wrapper launched by the agent's own config runs as the agent's user, so the agent can remove, bypass or kill it. HTTP across separate containers is a real boundary with one interceptable ingress. stdio behind the gateway is out of the agent's reach.

### D-006 · 2026-11-08 · accepted
**Decision:** the gateway issues an opaque session token bound to a role from server-side config. Any identity or role field in a request is ignored and logged as an impersonation attempt. No token passthrough.
**Rationale:** never trust identity the agent can write; the MCP spec names token passthrough as a confused-deputy cause.

### D-007 · 2026-11-08 · accepted
**Decision:** the audit log is JSONL with **RFC 8785** canonical JSON. Each entry has `seq`, `prev_mac` and an **HMAC-SHA256** `mac` (key held only by the gateway user). Heartbeat entries are written periodically, and a `proxy_start` entry records the policy and tool-definition hashes. The head is anchored to a store in the tool zone. The gateway fails closed if logging fails. Sigstore Rekor anchoring is a stretch goal.
**Rationale:** canonicalization avoids silent hash mismatches; the HMAC stops chain recomputation without the key; the anchor catches truncation; heartbeats catch kills; fail-closed preserves completeness.

### D-008 · 2026-11-08 · accepted
**Decision:** the platform is Docker Compose: agent, gateway and tool containers on two networks (`agent_net` and internal `tool_net`), non-root UIDs, plus an observer outside the zones. Attackers are scripted first; a real-LLM driver (owner's Claude API key) comes after M6.
**Rationale:** runs on a laptop, no cloud; network isolation makes "no route around the gateway" real and testable; scripted baselines are deterministic and free.

### D-009 · 2026-11-08 · accepted
**Decision:** during implementation, commit and push gradually as each step passes, as `faheemgurkani`, with no AI attribution. No force-push or history rewrite without asking.

### D-010 · 2026-11-09 · accepted
**Context:** with only the isolated reference setup, every attack is simply "blocked". That doesn't show *which* defence does the work, or how a typical deployment fares.
**Decision:** run every scenario against three **deployment profiles** of the same gateway code:
- `reference`: isolated zones.
- `breach`: the agent can write to the log volume, but has no key and no anchor.
- `colocated`: the gateway runs as the agent's own user, with the log, key, anchor and tool credential on the agent's disk. This is the usual real-world wrapper setup.
**Rationale:** it separates the value of isolation (reference vs colocated) from the value of the cryptographic layer (breach). The colocated profile also serves as the baseline that external gateways will be compared against in M8.

### D-011 · 2026-11-09 · accepted
**Decision:** the scripted attacker is the **strongest one the lab can justify**. It discovers targets itself (filesystem and `/proc` search, never handed paths). If it finds the key, it stops the gateway, rewrites the log with a recomputed chain and anchor, fills time gaps with forged heartbeats, and restarts the gateway with its original command line.
**Rationale:** a weak attacker makes defences look better than they are. The first colocated run showed truncation "detected" only because of an incidental time gap; a key-holding attacker can trivially forge heartbeats, so we model that.

### D-012 · 2026-11-09 · accepted
**Context:** the real-LLM runs showed the agent never even discovered `admin.delete_user`, because a user session's `tools/list` is role-filtered.
**Decision:** keep tool-list filtering by role as a first-class control, not just call-time authorization, and report it as defence in depth. Keep the real-LLM scorecard as a *lower bound* alongside the scripted *upper bound*, rather than replacing one with the other.
**Rationale:** hiding a tool's existence reduces what an agent can target; measuring both bounds is more honest than reporting only the strongest attacker or only a given model.

### D-013 · 2026-11-09 · accepted
**Context:** M8 scores third-party gateways, which raises disclosure questions.
**Decision:** (1) external gateways are driven in their native transport (stdio proxies run as a subprocess), not forced into the HTTP slot; attacks that don't apply to a transport are documented, not faked. (2) Results are framed as a **capability comparison**, never a vulnerability claim, unless a gateway fails a guarantee it actually makes — in which case contact the maintainer privately before any public writeup. Record each gateway's version.
**Rationale:** honest, reproducible comparison; respects maintainers of responsibly-scoped tools; avoids overclaiming.

### D-014 · 2026-11-09 · accepted
**Context:** owner asked to test the latest open-weight models, especially those claiming stronger safeguards.
**Decision:** test five — `openai/gpt-oss-safeguard-20b` (the only open, tool-capable model advertising a safeguard focus) plus the newest flagships from four other vendors (kimi-k3.1-pro, deepseek-v4.1-flash-1017, qwen3.8-flash, glm-5.3) — into a separate results file, keeping the gpt-oss-120b baseline intact. Budget guard cap $6 / floor $4.
**Rationale:** covers both "most recent" and "most safety-oriented"; vendor diversity; a separate file keeps the baseline reproducible and the new run re-runnable.

### D-015 · 2026-11-11 · accepted
**Context:** only one external gateway had been scored, with a one-off script, and the reference gateway's column in that comparison was hand-written.
**Decision:** one shared harness (`lab/adapters/harness.py`) scores every gateway, the reference gateway included, through the same attacks; an adapter is a small `Gateway(...)` description. Add **A12, rewrite the log and recompute the chain with the gateway's published algorithm (no key)**, because it is the attack that separates keyed or signed logs from plain hash chains. Each external gateway is installed in its own environment under `lab/.ext/` and pinned to the version scored.
**Rationale:** a measured reference column is more credible than a written one; a uniform harness makes the comparison fair and makes adding a gateway cheap; A12 tests the property that a "tamper-evident" log actually needs.

### D-016 · 2026-11-11 · accepted
**Context:** scoring more gateways turned up one whose measured behaviour differs from guarantees its documentation makes.
**Decision:** apply D-013 strictly: that gateway's adapter (`lab/adapters/embargoed.py`) and results (`lab/results/raw/`) stay git-ignored, the public scorecard says only that one more gateway was scored, and the owner contacts the maintainer privately before anything about it is published.
**Rationale:** responsible disclosure costs nothing here and protects both the maintainer's users and this project's credibility.

### D-017 · 2026-11-11 · accepted
**Context:** LLM-attacker evidence was 1–2 runs per cell.
**Decision:** raise every cell to 5 runs (6 models x 3 profiles x 3 framings), report a one-sided 95% Clopper-Pearson upper bound per model, and keep hand-written observations in `lab/scorecard/notes/*.md`, re-checked against the transcripts, instead of inside the report generator. Budget: cap $5 for the top-up, floor $5 left on the key.
**Rationale:** "0/N" means little without N; a bound states what the data supports. Prose inside a generator silently outlives the data it described.

### D-018 · 2026-11-11 · accepted
**Context:** the 5-model sweep showed agents reading the lab's own source in the agent image (`/app`), including the scripted attack code, and one run opened the git-ignored embargoed adapter, because the image copied all of `lab/`.
**Decision:** keep the gateway and lab **source** visible to the agent: a real attacker can read open-source code (Kerckhoffs), and hiding it would flatter the gateway. Exclude what an attacker should never see from the image via `.dockerignore`: embargoed adapters (D-016), past results and transcripts (`lab/results`), and external gateway installs (`lab/.ext`). Transcripts that touched embargoed material are redacted before commit, and scorecard notes say which successes read the lab's attack code.
**Rationale:** the threat model assumes a knowledgeable attacker; disclosure promises and the "answer key" of earlier runs are a different matter.

### D-019 · 2026-11-11 · accepted
**Context:** the reference gateway's argument rules were hard-coded Pydantic models for the three demo tools, so it could not front any other tool server (notes/05, Part 5 step 2).
**Decision:** argument rules are JSON Schemas, one per tool, taken from (first match wins) the operator's `--arg-rules` file, then the tool's own `inputSchema` captured at startup, then nothing (deny). Every object schema is **closed by default** (`additionalProperties: false` unless the schema says otherwise), JSON Schema never coerces types, and the rules' hash and per-tool source are logged in `proxy_start`. The demo's tighter rules (ID patterns, field enum, length cap) move to `tools/demo_server/arg-rules.yaml`.
**Rationale:** trusting the upstream schema is safe here only because pinning already quarantines a tool whose definition changes after startup, so the schema can't be swapped under the gateway. The operator file exists because advertised schemas are often loose (no patterns or lengths). Closing schemas by default keeps the smuggled-field defence (A7/A9) for tools whose authors forgot `additionalProperties`.

### D-020 · 2026-11-11 · accepted
**Context:** scoring a gateway needed a Python adapter in `lab/adapters/gateways.py`, a bespoke A12 forger per gateway, and a checkout of this repo (notes/05, Part 5 step 1).
**Decision:** ship an installable `mcp_lab` package with an `mcp-lab` CLI. A gateway is described by a small **YAML spec** (start command around `{{upstream}}`, config file templates, log path, verify command); `mcp-lab score spec.yaml` runs every attack and prints one table, with `--json`/`--markdown` output and a `--fail-on undetected` exit code for CI. A12 needs no bespoke code: a **generic forger** tries a catalogue of keyless schemes (hash field over the entry under several JSON serializations, with or without the previous hash prepended; previous-line hash), uses only schemes that **reproduce the untouched log exactly**, and moves any head copy in the gateway's directory along. The harness, demo tool server and reference adapter move into the package (`tools/demo_server/server.py` stays as a shim for the Docker lab). Also: `mcp-lab inspect-log` (what a log proves) and `mcp-lab check-deployment` (which profile a real setup is in), for the Part 4 audit and review uses.
**Rationale:** a gateway author can test their gateway without writing Python or reading the harness. Requiring a scheme to reproduce the clean log first means a "recomputed and accepted" result is itself proof the chain needs no secret, and a scheme we lack can only make the gateway look better ("n/a" or "detected"), never worse. Validated by **parity**: specs for all five external gateways reproduce the bespoke adapters' published results exactly, including every A12 forgery.

### D-021 · 2026-11-11 · accepted
**Context:** the owner chose not to contact any maintainer for now, the embargoed gateway's included, and asked whether the gateways' licenses allow publishing results about them in a technical report or publication.
**Decision:** outreach is deferred by the owner. Licenses were checked from the installed packages' own metadata and LICENSE files: mcp-gate-policy 0.3.2 Apache-2.0, shugo 0.1.0 MIT, mcp-glp-audit-proxy 0.4.0 MIT (Community edition; its `licence.py` only gates paid Pro features, which were not used), mcp-audit-proxy 0.1.0 Apache-2.0, and the embargoed gateway AGPL-3.0-or-later. None restricts benchmarking or publishing results (no benchmark clause), and this repo neither vendors nor redistributes their code: they are installed separately and driven through their public CLIs, and the specs in `examples/specs/` are configuration. Publishing factual, reproducible measurements of these open-source tools is therefore permitted by their licenses. **The embargo (D-016) stays in place**, because it rests on this project's own disclosure policy (D-013), not on licensing; lifting it is the owner's explicit call. The technical report covers the five public gateways and mentions the sixth only as withheld.
**Rationale:** separating "may we, legally" (yes) from "should we, ethically, before telling the maintainer" (the policy's question) keeps both decisions visible and reversible.

### D-022 · 2026-11-12 · accepted
**Context:** the owner asked for a citation template and an open invitation to collaborate (new attack vectors, techniques and more).
**Decision:** add `CITATION.cff` (CFF 1.2.0, validated with cffconvert; author Muhammad Faheem as in `LICENSE`), so GitHub shows "Cite this repository", plus a BibTeX entry in the README and a `@techreport` entry in the technical report. Add `CONTRIBUTING.md` with seven ways to contribute (attacks, gateway specs, forger schemes, deployment profiles, LLM attackers, reference-gateway upgrades, docs), each pointing at the exact file to change; issue templates for attack proposals and gateway specs; and `SECURITY.md`. The ground rules carry over this project's own principles: judge from outside the gateway, don't overclaim, disclose privately to a third-party maintainer first (D-013).
**Rationale:** citations and concrete entry points are what turn a portfolio repo into one others build on. Putting the disclosure rule into the contribution path keeps contributed results consistent with D-013.
**Open:** GitHub private vulnerability reporting is off for the repo; `SECURITY.md` relies on it. Turning it on is a repository setting, left to the owner.


### D-023 · 2026-11-14 · accepted
**Context:** the owner asked to verify the claim "colocated is how most stdio gateways are deployed today" (README, ARCHITECTURE, notes/04, notes/05).
**Decision:** reword it everywhere to what the protocol backs up: colocated is the **default** for a stdio gateway launched from the agent's own MCP config, since the client spawns it as the agent's OS user unless the operator isolates it. State that prevalence is unmeasured.
**Rationale:** no survey or telemetry on real stdio-gateway deployments was found, so "most" was an inference from the transport and from our six specs. Partial exceptions exist (Docker MCP Gateway containerises tool servers), and a growing share of 2026 gateway products are remote HTTP services, which are not colocated. Sources checked: 2026 gateway roundups (Geekflare, Maxim, Morph, MetaMCP guide, MintMCP).

### D-024 · 2026-11-14 · accepted
**Context:** the embargoed gateway's source host has a newer prerelease (2026-09-09) than the package-index version scored on 2026-11-11, and its main branch appeared to add signature checking. The disclosure draft described only the old version.
**Decision:** with owner approval, install the prerelease in its own pinned env under `lab/.ext/` and score it with the same spec, configured at its strongest: signatures on, the verifier run with signatures required and the trusted public key, and the key directory moved into each run's work directory. Rewrite the private draft to separate what is still open in the latest code from what is fixed but unreleased. The embargo (D-016) and the deferred outreach (D-021) are unchanged.
**Rationale:** a disclosure should describe the maintainer's current code, and publishing old-version results without that context would overstate the problems. Scoring the strongest configuration keeps the comparison fair (D-011).
