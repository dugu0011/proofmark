# Benchmarks — measuring Proofmark, and comparing it to Strix

Two scorers, both driven off a target's known bug classes (labels in
`expected_*.json`, matched by OWASP/CWE code):

- **`score.py`** — recall for a single Proofmark run.
- **`compare.py`** — Proofmark **vs** Strix on the same target, side by side.

## Single run

```bash
python benchmarks/score.py proofmark_runs/<run-id>
```

## Head-to-head vs Strix

1. Run Proofmark against the target (authorized):

   ```bash
   proofmark https://juice-shop.local --authorized --operator you \
     --output proofmark_runs/juice
   ```

2. Run Strix against the same target and save its report as JSON (e.g.
   `strix_report.json`). `compare.py` is schema-tolerant: it accepts a list of
   findings or a dict under `findings`/`vulnerabilities`/`results`/`issues`, and
   pulls OWASP/CWE codes out of each finding's text.

3. Compare:

   ```bash
   python benchmarks/compare.py \
     --proofmark proofmark_runs/juice \
     --strix strix_report.json \
     --expected benchmarks/expected_juice_shop.json
   ```

Example output:

```
Proofmark vs Strix — OWASP Juice Shop
==================================================================
  expected classes: A01, A02, A03, A05, A06, A07

  Proofmark    findings   3 | proven   3 | recall 0.33 (2/6) | matched A01, A03
  Strix        findings   2 | proven   0 | recall 0.33 (2/6) | matched A03, A05

  only Proofmark found: A01
  only Strix found:     A05

  proven-finding edge: Proofmark 3 vs Strix 0 (Proofmark)
```

## The two numbers

- **recall** — of the classes the target is known to contain, how many were found.
- **proven** — how many findings carry a reproduced proof-of-concept / captured
  evidence. This is Proofmark's differentiator: it proves what it reports, so a
  fair comparison shows both columns, not a raw finding count that rewards
  unproven noise.

Extend `expected_*.json` (add crAPI, VAmPI, etc.) as you validate more targets.
