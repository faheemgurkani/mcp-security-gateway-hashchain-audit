# Notes

A running record of how this project works and why it is built this way: every clarification the owner asks for, and every decision made. The aim is that the owner understands every system, architecture and design choice, even though implementation is delegated.

| File | Contents |
|------|----------|
| [00-project-overview.md](00-project-overview.md) | What the project is, the problem it solves, how it works end to end |
| [01-learning-resources.md](01-learning-resources.md) | Curated, trusted learning resources (standards, papers, books, courses) |
| [02-value-proposition.md](02-value-proposition.md) | *(superseded)* First positioning attempt |
| [03-research-validation.md](03-research-validation.md) | Independent validation: what already exists, the real gap, why my proposal fell short |
| [04-implementation-findings.md](04-implementation-findings.md) | Running log of findings during implementation and testing |
| [05-project-review.md](05-project-review.md) | Review against the owner's goals, gap closure with latest results, plain-language explanations, and the value stage (mcp-lab, testing, licenses, embargo) |
| [06-publishing-to-pypi.md](06-publishing-to-pypi.md) | Publishing to PyPI as `mcp-gateway-lab`, step by step: names, metadata, versions, auditing packages, TestPyPI, Trusted Publishing, the release checklist |
| [decisions.md](decisions.md) | Decision log (ADR-style): one entry per decision, with context, options, choice and rationale |

The lab produces scorecards in `docs/results/`: `scorecard.md` (scripted attacker, the upper bound), `scorecard-llm.md` (gpt-oss-120b baseline, a lower bound), `scorecard-llm-models.md` (five latest / safeguard-oriented open-weight models, including the first real-LLM success), and `scorecard-external.md` (external gateways vs the reference).

New topics get their own numbered file (`01-<topic>.md`, `02-<topic>.md`, …) and a row in this table.

The working implementation plan lives in [../PLAN.md](../PLAN.md). For users of the lab: [../GUIDE.md](../GUIDE.md) (six practical jobs) and [../report/technical-report.md](../report/technical-report.md) (the write-up).
