# 05 — Project review: what it is, how complete, does it meet the goals

Written 2026-11-11 for the owner's own learning. Part 1 is the review as given before the
gap-closing work; Part 2 records what changed afterwards, with the latest results. Part 3
is the plan for making the project useful to others.

The owner's goals for the project:
1. get hands-on with AI security engineering;
2. have a portfolio project;
3. deliver something other people can actually use.

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
- Real AI models had been run as attackers, and none got through.

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
| Thin AI-model evidence | ✅ **Closed for gpt-oss-120b**, ⏳ **five-model top-up in progress.** Raised to 5 runs per test, with confidence bounds. | `docs/results/scorecard-llm*.md`, D-017 |

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
qwen3.8-flash and glm-5.3.

- The run to 5 reps per cell (225 runs) is in progress.
- So far, no model has executed or tampered in any run.
- A few runs failed on OpenRouter rate limits; a resume pass redoes them.
- Budget: capped at $4.50, with a $5 floor kept on the key. Runs cost about
  $0.001–0.008 each.
- `scorecard-llm-models.md` and this section get updated when the run finishes.

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

## Part 3 — What would make it valuable to others (next phase, not started)

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
