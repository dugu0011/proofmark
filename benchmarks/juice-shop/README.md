# Accuracy test: Proofmark vs OWASP Juice Shop

The honest way to measure an agentic pentester is to point it at a known-vulnerable
app you control and see what it *proves*. [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
is the standard target: dozens of planted vulnerabilities across the OWASP Top 10.

This is the one test only you can run — it needs your LLM key.

## Run it

```bash
export ANTHROPIC_API_KEY=...     # or OPENAI_API_KEY / AZURE_API_KEY
cd benchmarks/juice-shop
./run.sh graph                   # recon -> exploit; use ./run.sh for a single agent
```

The script starts Juice Shop on `:3001`, waits for it, runs `proofmark doctor`,
then scans it. When it finishes you get:

- `juice-shop-report.md` — every finding the agent **proved**, with its
  proof-of-concept, confidence, OWASP category and CWE
- `proofmark_runs/<id>/` — the signed, tamper-evident run record. Verify it with
  `proofmark verify proofmark_runs/<id>` and re-check the exploits with
  `proofmark replay proofmark_runs/<id>`

## What to look for (this is the accuracy read)

- **False positives:** open the report and check each PoC actually demonstrates
  the bug. By design there should be near-zero phantoms — a finding without a
  reproduced PoC is refused by the engine.
- **Confidence:** low-confidence findings are flagged as such — treat them as
  leads, not conclusions.
- **Coverage:** which classes it found (injection, broken access control, XSS,
  etc.) versus what Juice Shop plants. This is where the LLM's competence shows;
  a bigger model and a higher `--max-steps` find more.
- **No duplicates:** the same bug is recorded once.

## Notes

- **macOS / Windows (Docker Desktop):** works as-is — the sandbox reaches the host
  at `host.docker.internal`.
- **Linux:** `host.docker.internal` is not automatic. Either run Juice Shop and
  point Proofmark at the container's IP on a shared Docker network, or add
  `--add-host=host.docker.internal:host-gateway` when starting the sandbox image.
- Only ever run this against Juice Shop or another target you own. The scan
  refuses any host outside the one you point it at.
- Stop the target when done: `docker rm -f juice-shop`.
