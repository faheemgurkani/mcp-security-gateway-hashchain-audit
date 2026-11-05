# 01: Learning resources for AI security engineering

Researched 2026-11-05/06. These were chosen because practitioners actually cite them, they are current, and they relate to this project (MCP/agent tool security plus audit logging). The list starts with primary sources, meaning standards bodies, the protocol's own docs and peer-reviewed research. Vendor courses come later and are marked as such.

## A. Core references (free; read these first)

| # | Resource | Why it matters here | Time |
|---|----------|---------------------|------|
| 1 | **MCP Security Best Practices** (official spec), https://modelcontextprotocol.io/specification/latest/basic/security_best_practices | The protocol's own text on the **confused deputy** and **token passthrough** (servers MUST NOT accept tokens not issued to them). Our gateway's policy layer exists to address this. | 1 h |
| 2 | **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10, published Dec 2025, 100+ contributors), https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026 | The industry vocabulary. Our project targets **ASI02 Tool Misuse** and **ASI03 Identity & Privilege Abuse**, plus the forensics/rogue-agent concerns. Map every feature we build to an ASI ID. | 2 h |
| 3 | **OWASP Top 10 for LLM Applications** (genai.owasp.org) | The base layer the agentic list extends (prompt injection, excessive agency). | 1 h |
| 4 | **Microsoft "MCP for Beginners", Security module**, https://github.com/microsoft/mcp-for-beginners/blob/main/02-Security/README.md | Hands-on, beginner-friendly MCP security walkthrough with code. | 2 h |
| 5 | **MITRE ATLAS**, https://atlas.mitre.org | The ATT&CK-style catalogue of AI attacks; it now includes agent techniques such as tool credential harvesting and poisoned agent tools. Use it to name the attacks in our threat model. | browse |

## B. Research papers (the "why" behind defences)

| # | Paper | Key idea for us |
|---|-------|-----------------|
| 6 | **Defeating Prompt Injections by Design (CaMeL)**, Debenedetti et al., Google/ETH, arXiv:2503.18813 | Don't try to *detect* injections; enforce **policies at tool-call time** with capabilities. This is exactly where our gateway sits. Code: github.com/google-research/camel-prompt-injection |
| 7 | **Design Patterns for Securing LLM Agents against Prompt Injections**, Beurer-Kellner, Tramèr et al., arXiv:2506.08837 | Six patterns (plan-then-execute, dual LLM, etc.). Main lesson: application-specific agents with clear trust boundaries. Our policy file *is* such a trust boundary. |
| 8 | **Invariant Labs, tool-poisoning disclosure** (Apr 2025; now Snyk Agent Scan / `mcp-scan`) | Coined "tool poisoning", "tool shadowing", "rug pull" and "toxic flows". These are the attacks the demo should reproduce. |

## C. Tamper-evident logging (Stage 11 half)

| # | Resource | Key idea |
|---|----------|----------|
| 9 | **RFC 9162: Certificate Transparency v2** | The internet's production-grade tamper-evident log (Merkle trees, inclusion/consistency proofs). Our hash chain is the simple version of this. |
| 10 | **C2SP specs: tlog-checkpoint, signed-note, tlog-witness** (github.com/C2SP/C2SP) | How to **anchor** a log's latest hash with signatures and independent "witnesses", so even the log operator can't rewrite history silently. This is the upgrade path past "hash chain only". |
| 11 | **EU AI Act, Article 12 (record-keeping)** + **NIST AI RMF 1.0** | The compliance "why". Note: commentators disagree on whether Art. 12 needs *cryptographic* tamper evidence; it requires automatic, traceable logging. The Aug 2, 2026 high-risk date is widely cited but its current status is **unverified** (there were delay proposals). Check EUR-Lex before claiming compliance. |

## D. Books (pick one)

- **AI-Native LLM Security**, Malik, Huang & Dawson (Packt, Dec 2025). Ads Dawson was founding tech lead of the OWASP LLM Top 10. Most aligned with the OWASP framing.
- **Practical AI Security**, Harriet Farlow (No Starch, 2026). A reviewer praises the threat-modeling chapters; the red-team content is introductory.

## E. Courses / certifications (paid, vendor-run; optional, later)

- **SANS SEC545: GenAI & LLM Application Security**: the most established; includes labs attacking agent infrastructure via MCP and MAESTRO threat modeling.
- **OffSec AI-300 (OSAI+)**: advanced AI red teaming; for later.
- **AppSecEngineer AI Agent Security Masterclass**: hands-on tool abuse and least-privilege labs.
- Prices, dates and seat availability were **not verified**.

## Suggested order for a beginner (≈1 day of reading, alongside building)
1 → 2 → 4 → 6 (abstract and intro only) → 9 (overview section only). Read the rest as each component gets built.

## Caveats
- Several web summaries cited figures (an NSA MCP advisory of May 2026, a 2026-07-28 MCP spec revision, ATLAS technique counts) that came from secondary sources only. They are not repeated as fact anywhere in this repo until verified.
- No resources were downloaded; everything above is free online except books and courses.
