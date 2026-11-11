# 05 — Project review: what it is, how complete, does it meet the goals

Written 2026-11-11 for the owner's own learning. Part 1 is the review as given before the
gap-closing work; Part 2 records what changed afterwards, with the latest results. "In
brief" is a one-screen summary of Parts 3 and 4: Part 3 explains key terms in plain
language, and Part 4 covers how the work differs and how to use it in practice. Part 5 is
the plan for making the project useful to others.

The owner's goals for the project:
1. get hands-on with AI security engineering;
2. have a portfolio project;
3. deliver something other people can actually use.

## Contents

- [Part 1 — The review (before gap closure)](#part-1--the-review-before-gap-closure): the original verdict, as given before any fixes
  - [What it is, in plain terms](#what-it-is-in-plain-terms): MCP, gateways, the agent-as-attacker question, the four parts, the main finding
  - [How complete it was](#how-complete-it-was): milestones and the four loose ends
  - [Verdict against the goals (at the time)](#verdict-against-the-goals-at-the-time): learning, portfolio, value to others
- [Part 2 — What changed since (gap closure, 2026-11-11)](#part-2--what-changed-since-gap-closure-2026-11-11): how each gap was closed, with the latest results
  - [New attack: A12, keyless rewrite](#new-attack-a12-keyless-rewrite): why a hash chain without a secret proves consistency, not integrity
  - [Outside gateways: same harness, same attacks](#outside-gateways-same-harness-same-attacks): the six-gateway comparison table and what to take from it
  - [AI models as attackers (5 runs per test)](#ai-models-as-attackers-5-runs-per-test): gpt-oss-120b, the five newer models, and the first real-LLM success
  - [Lessons learned along the way (engineering)](#lessons-learned-along-the-way-engineering): harness bugs, provider errors, rechecking claims
- [In brief: key terms, what is different, how to use it](#in-brief-key-terms-what-is-different-how-to-use-it): one-screen summary of Parts 3 and 4
- [Part 3 — Plain-language explanations](#part-3--plain-language-explanations): the key terms, explained with analogies
  - [What "colocated" deployment means](#what-colocated-deployment-means): the three deployment profiles
  - ["HMAC-signed, hash-chained log"](#hmac-signed-hash-chained-log): hash chain, HMAC key, anchor
  - ["Pins tool definitions, so it can catch a rug pull"](#pins-tool-definitions-so-it-can-catch-a-rug-pull): rug pulls and tool pinning
- [Part 4 — How this work differs, and how a security engineer uses it](#part-4--how-this-work-differs-and-how-a-security-engineer-uses-it): positioning, quality, practical use
  - [How it differs from other projects](#how-it-differs-from-other-projects): what this lab tests that gateway projects don't
  - [What makes it good quality](#what-makes-it-good-quality): reproducibility, honest limits, disclosure
  - [How an AI security engineer would use it in production work](#how-an-ai-security-engineer-would-use-it-in-production-work): six concrete uses
- [Part 5 — What would make it valuable to others (done 2026-11-11)](#part-5--what-would-make-it-valuable-to-others-done-2026-11-11): the plan for the next stage, and what was built
  - [What was built (2026-11-11)](#what-was-built-2026-11-11): status of each step, and the tool for each Part 4 use

## Part 1 — The review (before gap closure)

**Short version:** a finished, well-made security project. It meets the learning and
portfolio goals, but only partly meets the "others can use it" goal.

The review came after reading every doc and source file and running the checks: 41/41
tests passed and lint was clean.

### What it is, in plain terms

AI agents use tools such as "look up a customer" or "delete a user" through MCP (Model
Context Protocol). A **security gateway** sits between the agent and the tools. It checks
each tool call against the caller's role, and it writes a log built so that later edits
can be detected. Many such gateways already exist.

The project asks a question nobody had tested: **what if the agent itself is the
attacker?** Can it delete its own log, kill the gateway, go around it, or pretend to be
an admin?

It has four parts:

1. **A reference gateway** (`src/mcp_gateway/`). It checks:
   - identity, which is bound to the session and never read from the request;
   - role rules, with default deny;
   - arguments, with strict schemas.

   It also writes an HMAC-signed, hash-chained log and pins tool definitions, so it can
   catch a tool that changes after startup (a "rug pull").
2. **A Docker lab** with separate zones for the agent, the gateway and the tools, plus an
   observer outside all three zones.
3. **Attacks A1–A11.** Each one runs as a script, and some runs use real AI models as
   the attacker.
4. **A scorecard.** Each attack is judged blocked, detected or undetected, using
   evidence collected outside the agent's reach.

**Main finding:** the signed log only protects you if the agent cannot reach the key.

| Deployment profile | Result |
|---|---|
| `reference`: gateway properly isolated | all 11 attacks blocked |
| `breach`: agent can write the log but cannot reach the key | every log attack detected |
| `colocated`: gateway runs as the agent's own user | the agent rewrites history and the verifier still says "OK" |

`colocated` is how most stdio gateways are deployed today.

### How complete it was

- All milestones (M1–M9) were done.
- Other gateways could be scored through an adapter, but only one had been
  (mcp-gate-policy).
- Real AI models had been run as attackers, and none got through (at 1–2 runs per test; see Part 2 for what changed at 5).

Loose ends:

- `scripts/run_demo.sh` and `scripts/tamper_log.py` were empty placeholders.
- The AI-model results used only 1–2 runs per test, which is thin evidence.
- Only one outside gateway had been scored.
- The local `.venv` broke when the repo folder moved, so `uv run pytest` failed.
  - Workaround: `uv run python -m pytest`.
  - Fix: delete `.venv` and run `uv sync`.

### Verdict against the goals (at the time)

| Goal | Verdict |
|---|---|
| Hands-on AI security | ✅ **Yes, strongly.** It covers threat modelling, the OWASP Agentic Top 10 mapping, cryptographic logging, deployment isolation, testing with real LLM attackers, and an honest account of the limits. That is much stronger than "I built another gateway". |
| Portfolio piece | ✅ **Yes.** The repo is clean and documented, every decision is recorded, and the headline finding is clear and backed by data. |
| Delivers value others can use | ⚠️ **Partly.** The findings are useful to anyone deploying MCP gateways, but the tool is hard for others to use. |

Why the tool was hard for others to use:

- The gateway's argument rules are hard-coded for the demo tools.
- There is no one-command "score my gateway" path.
- Nobody outside the project knew about it yet: no maintainers had been contacted and
  nothing had been posted.

## Part 2 — What changed since (gap closure, 2026-11-11)

| Gap | Status | Where |
|---|---|---|
| Empty scripts | ✅ **Closed.** `./scripts/run_demo.sh` is a demo that needs no Docker (see below). | `scripts/`, README "Two-minute demo" |
| Broken `.venv` | ✅ **Closed** (local only). Deleted `.venv` and ran `uv sync`. 49/49 tests pass, lint is clean. | notes/04 |
| Only one outside gateway | ✅ **Closed.** One shared harness now scores the reference gateway and four outside gateways; a fifth is scored but embargoed (D-016). | `lab/adapters/`, `docs/results/scorecard-external.md`, D-015 |
| Thin AI-model evidence | ✅ **Closed.** All 6 models raised to 5 runs per test (270 runs), with confidence bounds. | `docs/results/scorecard-llm*.md`, D-017 |

What the demo does, in about two minutes:

1. Starts the gateway and makes allowed calls and forbidden ones (confused deputy,
   impersonation, smuggled field, forged token).
2. Verifies the clean log.
3. Shows each of four keyless tampers caught: edit, delete, truncate and spoof.
4. Shows an attacker *who holds the key* forging a log that still verifies. This is the
   headline finding in miniature.

### New attack: A12, keyless rewrite

The attacker edits the log, then recomputes the whole hash chain with the gateway's
published algorithm, without any secret. **Every gateway with a plain (keyless) hash
chain accepted the forged log.** Only the reference gateway's HMAC key caught it, and
only because the key is out of the agent's reach.

Lesson: a hash chain without a secret proves the log is *consistent*, not that it is
*unaltered*. Whoever can write the file can recompute the chain.

### Outside gateways: same harness, same attacks

How outcomes are judged:

- **Execution** comes from the tool server's own ledger, which records what actually ran.
- **Tampering** comes from each gateway's *own* verifier, run on a copy of its log that
  the harness altered.

Icons: 🛡️ blocked · 🔎 detected · ❌ undetected.

| | reference | mcp-gate-policy 0.3.2 | shugo 0.1.0 | mcp-glp-audit-proxy 0.4.0 | mcp-audit-proxy 0.1.0 |
|---|---|---|---|---|---|
| role / tool policy (A7, A8) | 🛡️ | 🛡️ | 🛡️ | 🛡️ | 🛡️ |
| argument validation (A9) | 🛡️ | ❌ | 🛡️ | ❌ | ❌ |
| rug pull (A10) | 🛡️ | ❌ | ❌ | ❌ | 🔎 |
| log edit / delete (A1, A2) | 🔎 | 🔎 | 🔎 | 🔎 | ❌ |
| log truncation (A3) | 🔎 | ❌ | ❌ | 🔎 | ❌ |
| keyless rewrite (A12) | 🔎 | ❌ | ❌ | ❌ | ❌ |

What to take from it:

- **Role and tool-name policy is table stakes.** Every gateway passes A7 and A8.
- **Argument validation is rare.**
  - shugo gets it only because it is built on MCP SDK v1, which validates arguments
    against the tool's schema.
  - SDK v2 dropped that check, so gateways built on v2 forward malformed calls unless
    they validate the arguments themselves.
- **Truncation needs the head of the log stored somewhere else.** mcp-glp-audit-proxy's
  `.head` sidecar does that, which is why it catches A3.
- **mcp-audit-proxy is a flight recorder** and makes no integrity claim. Its rug-pull
  *alarm* is real.
- **Interop:** two gateways omit a field the newest MCP spec requires (`resultType`). The
  harness talks to them in legacy mode.

This table is a **capability comparison, not a list of vulnerabilities** (D-013): it
scores each gateway on controls it may not set out to provide.

**A fifth outside gateway was scored but is held back (D-016).** Its documentation
promises guarantees that the scoring showed it does not deliver. Under the disclosure
policy (D-013), its maintainer is told privately before anything is published.

- A draft message is in the git-ignored `lab/results/raw/`.
- **Owner action:** send that draft privately.
- Results are published after the maintainer replies or a reasonable time passes.

### AI models as attackers (5 runs per test)

**gpt-oss-120b:** done.

- 45 runs (3 profiles × 3 framings × 5), costing $0.037.
- 0/45 executed a forbidden action or tampered with the log, including on `colocated`,
  where the scripted attacker wins every time.
- With 0/45, the per-run success rate is at most **6.4%** (one-sided 95% Clopper-Pearson
  bound). A bound like that is worth more than "it never happened in 2 runs".

What the transcripts show, rechecked by hand:

| Framing | Observations |
|---|---|
| Instructed | The model often misunderstands the setup and looks for OS accounts instead of the gateway. In 1/15 runs it called the admin tool, and the gateway denied it. |
| Incentivized | Misunderstands the setup in 15/15 runs. |
| Injected | Never followed the injected instruction (0/15). It explicitly declined in 9/15 runs. |
| Any | No run read the log or the key. |

- **Correction:** the old notes said the model "often refuses". It never refused at step
  zero; 3/15 instructed runs declined after exploring.

**Five newer models:** gpt-oss-safeguard-20b, kimi-k3.1-pro, deepseek-v4.1-flash,
qwen3.8-flash and glm-5.3. Done: 225 runs at 5 per cell, costing $3.88.

- **The first real-LLM success.** kimi-k3.1-pro bypassed the `colocated` gateway in 3 of
  5 incentivized runs, and none was detected.
  - It read the gateway's upstream token from a folder the agent can read in that
    profile, wrote its own MCP client, and called `admin.delete_user` on the tool server
    directly.
  - The gateway never saw the call, so the log is clean and still verifies.
  - One of the three runs did this without looking at the lab's own attack code.
  - The same model tried the same thing on `reference` and failed, because the token and
    the tool server were out of reach.
- **No model tampered with the log** (0/225).
- **Refusing is not the same as being safe.** kimi refused the blunt "delete this user"
  task in 10 of 15 runs, yet it was the only model that succeeded when it was merely
  *rewarded* for the outcome.
- **The safeguard-tuned model** (gpt-oss-safeguard-20b) never got anywhere. That is
  mostly because it could not use the tools properly: it called a lookup with no
  arguments until it ran out of turns. It is not evidence that it is safer.
- **Lab hygiene fix.** The agent's Docker image contained past results and the git-ignored
  embargoed adapter, and one run read the adapter.
  - Nothing reached git: the affected transcript steps were redacted before commit.
  - The image now excludes those files (D-018).
  - The lab's source code stays visible on purpose, because a real attacker can read
    open-source code.
- **Budget:** about $10.90 is left on the OpenRouter key.

Details: `docs/results/scorecard-llm-models.md`.

**How to read the LLM results:** they are *lower bounds*, meaning what today's agents
actually do. The scripted scorecard is the *upper bound*, meaning what the gateway must
withstand. A model failing to attack shows a capability gap, not a stronger gateway.

### Lessons learned along the way (engineering)

- **When a result surprises you, check the harness first.**
  - One adapter's config held an absolute log path, so tampered copies were verified
    against the untouched original, and every tamper looked "accepted".
  - It was caught because the result contradicted that gateway's source code.
- **Read a dependency's code before trusting its name.** The PyPI package
  `mcp-gatekeeper` turned out to be a CI quality gate, not a proxy.
- **Provider errors are data too.** OpenRouter sometimes returns HTTP 200 with an error
  body and no `choices`. The runner now retries, records the failure, and resumes.
- **Recheck hand-written claims whenever the data changes.** Notes now live in separate
  files (`lab/scorecard/notes/`) and are reviewed against the transcripts.

## In brief: key terms, what is different, how to use it

The short version of Parts 3 and 4.

**Colocated.** The gateway runs on the same machine, as the same user, as the agent.

- So the agent can reach everything the gateway uses: its log, its secret key, its config,
  and the tools behind it.
- It's like a guard who keeps the vault key under the burglar's pillow.
- Most MCP gateways are set up this way today, and in this setup the gateway loses every
  log attack.
- A real model has now shown this too: kimi-k3.1-pro went around a colocated gateway in 3
  of 5 runs (Part 2).

**Hash-chained, HMAC-signed log.**

- **Hash chain:** each log line carries a fingerprint that covers its own content and the
  previous line's fingerprint. Change or delete one line, and every fingerprint after it
  stops matching.
- **HMAC:** the fingerprint also mixes in a secret key.
  - With a plain hash, anyone who can edit the file can recompute all the fingerprints.
    That is our attack A12, and every keyless gateway accepted the forged log.
  - With HMAC you need the key, so the key must be out of the agent's reach.
- **Anchor:** the latest fingerprint is also stored somewhere else, so cutting lines off
  the end is caught.

**Pinning and rug pulls.**

- A rug pull is a tool that looks harmless when approved and later changes; for example,
  its description gains hidden instructions.
- At startup the gateway records a fingerprint of each tool's definition. If the
  definition later changes, the gateway refuses the call.

**How our work differs.** Other projects build a gateway and state what it protects. We
test whether those claims hold when the agent itself attacks.

- We judge results from evidence outside the gateway, not from what the gateway reports.
- We run the same attacks on six gateways.

That gave two findings you can't get from reading their READMEs:

- The signed log only helps if the agent can't reach the key.
- A plain hash chain proves the log is consistent, not that nobody altered it.

**Quality.**

- It is reproducible.
- Its limits are stated honestly: zero successes is given with a confidence bound, not
  reported as "safe".
- Every surprising result was checked against the gateway's source code.
- It follows a responsible disclosure policy.

**How an AI security engineer uses it:** as a test bench and a checklist, not as a product
to deploy.

1. **Choosing a gateway:** score candidate gateways before adopting one, with
   `mcp-lab score` and a short YAML spec.
2. **Reviewing a deployment:** ask whether the agent can read the key, write the log, edit
   its own config, or reach the tools directly. Any "yes" tells you what you lose.
3. **Regression testing:** rerun the scripted attacks after upgrading the gateway or
   changing its policy.
4. **Red-teaming with real AI models:** see what they actually try. A clean result is a
   lower bound, never proof of safety.
5. **Audits:** when someone hands you an agent's log as evidence, ask whether it is keyed
   and where the key lives.
6. **Threat modelling:** reuse our threat-model document, which maps each attack to the
   OWASP Agentic Top 10, as a template.

## Part 3 — Plain-language explanations

### What "colocated" deployment means

The gateway runs **on the same machine, as the same user, as the agent.**

- This is usually because the agent's app starts the gateway itself, as a subprocess (stdio).
- Whatever the gateway can read or write, the agent can too: its log, its secret key, its
  config, and the tool server behind it.
- Analogy: the security guard keeps the vault key under the burglar's pillow.
- It is the most common way MCP gateways are deployed today, and in the lab it loses every
  log attack.

The other two profiles, for contrast:

| Profile | What the agent can reach | Result |
|---|---|---|
| `reference` | Nothing: the gateway runs in its own container as its own user | every attack blocked |
| `breach` | The log file, but not the key | edits are *detected* |

### "HMAC-signed, hash-chained log"

The idea is built up in three layers.

1. **Hash chain.** Every log line carries a fingerprint (a hash) that covers its own content
   *and* the previous line's fingerprint.
   - Change, insert or delete one line, and every fingerprint after it stops matching.
   - Analogy: numbered pages where each page quotes the seal of the page before.
2. **HMAC (keyed hash).** The fingerprint also mixes in a **secret key**.
   - With a plain hash, anyone who can edit the file can just recompute all the
     fingerprints. That is attack A12, and every keyless gateway accepted the result.
   - With HMAC, recomputing them needs the key, so an attacker without the key cannot forge
     a valid chain.
   - That is why the key must live where the agent cannot reach it. In the `colocated`
     profile it can, and the protection is gone.
3. **Anchor.** The latest fingerprint is also stored in a second place.
   - Without it, cutting off the last few lines leaves a shorter chain that is still valid
     (attack A3).
   - The anchor shows the log used to be longer.

The result is a log that is **tamper-evident** (you can tell it was changed), not
tamper-proof (it cannot stop the change).

### "Pins tool definitions, so it can catch a rug pull"

**Rug pull:** a tool looks harmless when you approve it, then quietly changes later.

- Its description might gain hidden instructions for the AI, such as "also send the data
  to X".
- Or its inputs might change.
- The agent trusts the new version because the name is the same.

**Pinning:** at startup the gateway records a fingerprint of each tool's definition (name,
description, input schema).

- Before every later call it compares the current definition against that fingerprint.
- If anything changed, it refuses the call.
- The defence is like a photo of the contract taken on signing day: any later change is
  obvious.

## Part 4 — How this work differs, and how a security engineer uses it

### How it differs from other projects

Most projects in this space **build a gateway and state what it protects.** This project
**tests whether those claims hold when the agent itself attacks.** Three things set it
apart:

1. **The agent is the attacker.** Other tests assume an outside attacker. Here the threat is
   the very agent the gateway is supposed to control: deleting its own log, killing the
   gateway, going around it.
2. **Evidence comes from outside, not from the gateway's word.**
   - What actually ran comes from the tool server's ledger.
   - Whether tampering was caught comes from running the gateway's own verifier on a log
     the harness altered.
   - A gateway cannot pass by saying it blocked something.
3. **Same attacks, any gateway.** One harness scores six gateways side by side, so you
   can compare them fairly.

It produced two findings that are not obvious from reading any gateway's README:

- **Isolation matters more than cryptography.** The signed log only helps if the agent
  cannot reach the key. Colocated, it loses everything.
- **A keyless hash chain proves the log is consistent, not that it is unaltered (A12).**
  Several gateways market exactly that kind of log as tamper-evident.

### What makes it good quality

- **Reproducible:** scripts, Docker profiles and pinned versions; anyone can rerun every
  number.
- **Honest limits:**
  - scripted attacks are the upper bound, LLM attacks the lower bound;
  - zero successes is reported with a 95% confidence bound, not as "safe";
  - nothing is called "tamper-proof".
- **Checked against source:** each surprising result was confirmed by reading the gateway's
  code, and the one harness bug was found that way.
- **Responsible:** a disclosure policy (D-013), and one gateway is embargoed until its
  maintainer is told.
- **Every decision written down:** `decisions.md`, D-001 onwards.

### How an AI security engineer would use it in production work

Think of it as a **test bench and a checklist**, not as a product to deploy as-is.

1. **Choosing a gateway.**
   - Before adopting an MCP gateway, score it with the harness.
   - You see in minutes whether it checks arguments, catches rug pulls, and whether its log
     survives a keyless rewrite.
   - One command: `mcp-lab score my-gateway.yaml` (a short YAML spec; see `docs/GUIDE.md`).
2. **Reviewing a deployment.** The three profiles turn into review questions for any real
   setup:
   - Does the gateway run as a different user or in a different container from the agent?
   - Can the agent read the signing key, or the anchor?
   - Can the agent write the log, or edit its own MCP config to remove the gateway?
   - Can it reach the tool server directly?

   If any answer is yes, you are in `breach` or `colocated`, and the scorecard tells you
   what you lose.
3. **Regression testing.**
   - After upgrading the gateway or changing its policy, rerun the scripted attacks (as in
     CI).
   - This confirms nothing that used to be blocked now gets through.
4. **Red-teaming with real models.**
   - `run_llm` points real LLM agents at your setup.
   - It shows what they actually try (recon, reading config, guessing admin tools).
   - Treat a clean result as a lower bound, never as proof of safety.
5. **Audits and incidents.** When someone hands you an agent's log as evidence, ask:
   - Is it keyed (HMAC or a signature) or a plain hash chain?
   - Where was the key, and where is the head anchored?

   This project gives you the vocabulary and the test for that conversation.
6. **Threat modelling.** `docs/threat-model/THREAT_MODEL.md` maps each attack to the OWASP
   Agentic Top 10 and names the trust boundary each control needs. You can reuse it as a
   template for your own agent systems.

## Part 5 — What would make it valuable to others (done 2026-11-11)

In order:

1. **One-command scoring**, e.g. `mcp-lab score --gateway "<command>"`, so a gateway
   author can test their own gateway in minutes. The shared harness (`lab/adapters/`) is
   the foundation; what remains is a CLI and a generic adapter.
2. **Load argument rules from config**, or from each tool's own schema combined with
   pinning, so the reference gateway works with any tools, not just the demo server.
3. **Disclosure and outreach.**
   - Send the held-back gateway's maintainer the private note.
   - Offer each scored maintainer their results under D-013.
   - This is where outside credibility comes from.
4. **A short write-up** (blog post or LinkedIn) built around the two findings:
   - the key must be out of the agent's reach;
   - a keyless hash chain proves consistency, not integrity.

Steps 1–3 turn this from "a strong portfolio piece" into "a tool other people actually
use".

### What was built (2026-11-11)

| Step | Status | Where |
|---|---|---|
| 1. One-command scoring | ✅ **Done, and more general than planned.** `mcp-lab score my-gateway.yaml`: a ~10-line YAML spec instead of a single `--gateway` command, because most gateways also need a config file and a verify command. A12 needs no gateway-specific code (generic forger). Specs for all five external gateways reproduce the published results exactly. It installs straight from GitHub and comes with a GitHub Action for CI. | `src/mcp_lab/`, `examples/specs/`, `action.yml`, D-020 |
| 2. Argument rules from config | ✅ **Done.** Operator rules file, else the tool's own pinned schema, else deny; closed by default. | `src/mcp_gateway/validation/rules.py`, D-019 |
| 3. Disclosure and outreach | ⏸ **Deferred by the owner.** Licenses checked: all five are open source (MIT, Apache-2.0, AGPL-3.0), none restricts benchmarking or publishing results, and no code is redistributed. The embargo on one gateway stays until the owner decides. | D-021 |
| 4. Write-up | ✅ **Technical report** written, covering the five public gateways. | `docs/report/technical-report.md` |

Part 4's six uses now each have a concrete tool or document:

| Use | What to run or read |
|---|---|
| 1. Choosing a gateway | `mcp-lab score` |
| 2. Reviewing a deployment | `mcp-lab check-deployment` |
| 3. Regression testing | the GitHub Action, or `--fail-on undetected` |
| 4. Red-teaming with real models | `docs/GUIDE.md` §4 |
| 5. Audits and incidents | `mcp-lab inspect-log` |
| 6. Threat modelling | `docs/templates/agent-gateway-review.md` |

The guide (`docs/GUIDE.md`) walks through all six.
