# Proofmark

**An AI agent that finds and _proves_ real vulnerabilities in code you own.**

Most scanners tell you something *looks* wrong and leave you to sort the real
bugs from the noise. Proofmark works the other way: it runs an autonomous agent
that probes your application inside a sandbox, forms a hypothesis, and then
**reproduces the exploit** before it says a word. Every finding comes with a
proof-of-concept — the request it sent and the response that proves the impact.
If it can't prove it, it doesn't report it.

> ⚠️ Proofmark actively exploits its target. Only run it against systems you own
> or are explicitly authorized to test. It will not start without you asserting
> that authorization, and it records the assertion in every report.

## How it works

1. You point it at a target and assert authorization.
2. It starts a throwaway Docker sandbox — capped, isolated, no host access.
3. An LLM-driven agent works the target through tools: send HTTP requests, run
   commands, take notes. It plans, acts, observes, and repeats.
4. When it reproduces a vulnerability, it records it **with the PoC**.
5. You get a Markdown report of only what it could prove.

The agent runs entirely inside the sandbox, and a scope guard refuses any request
to a host you didn't authorize — enforced in code, not just asked of the model.

## Every run is signed, verifiable, and replayable

This is the part built for the security team, not just the developer. Every scan
writes a **tamper-evident run record** to `proofmark_runs/<id>/`: what was
authorized, every step the agent took, every request it sent, and what it proved
— with the steps hash-chained so any later edit is provable.

```bash
proofmark verify proofmark_runs/20260101-120000    # is this record intact?
proofmark replay proofmark_runs/20260101-120000    # does the exploit still work?
```

Set a signing key and records become attributable too, not just unaltered:

```bash
export PROOFMARK_SIGNING_KEY=...    # HMAC-signs every run record
```

An autonomous agent that *exploits* your systems is only adoptable if you can
prove afterwards exactly what it did and that the record wasn't touched. That's
what this gives you.

## Install

```bash
pip install -e .          # from a clone
proofmark doctor          # check Docker + your LLM key are ready
proofmark build-sandbox   # optional: build the Chromium image for the browser tool
```

You need Docker running and an API key for your model of choice:

```bash
export ANTHROPIC_API_KEY=...      # for anthropic/… models (default)
# or OPENAI_API_KEY / AZURE_API_KEY
```

## Use

```bash
# A live URL you own
proofmark scan -t https://staging.my-app.test --authorized --operator you@team.com

# A local codebase — the agent reads AND runs it in the sandbox to prove bugs
proofmark scan -t ./my-service --authorized --operator you@team.com

# A git repo (shorthand or full URL)
proofmark scan -t owner/repo --authorized

# Choose a model, write the report to a file, widen the scope
proofmark scan -t https://my-api.test \
  --authorized \
  --model openai/gpt-4o \
  --allow-host cdn.my-app.test \
  -o report.md
```

Proofmark exits non-zero when it proves at least one finding, so CI can gate on
it.

### In CI

Proofmark ships a packaged GitHub Action — add it to a workflow to gate pull
requests:

```yaml
- uses: dugu0011/proofmark@v1
  with:
    target: ${{ vars.PREVIEW_URL }}   # a deployed preview you own
    authorized: "true"
    strategy: graph                    # recon -> exploit
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The job fails if a vulnerability is proven (configurable with `fail-on-findings`),
and the report is uploaded as an artifact. A full example is in
[`.github/workflows/example-scan.yml`](.github/workflows/example-scan.yml).

## Status

Early, but it tests **live URLs and code** already.

- [x] Live URL targets — the agent probes and validates from inside the sandbox
- [x] Code targets — a local path or a git repo. The source is copied into the
      jail; the agent reads it (`list_files` / `read_file` / `search_code`), can
      run it, and exploits the running app over loopback to produce a real PoC.
      This is the edge: *code in, running exploit out* — not static guessing.
- [ ] A richer tool suite: headless browser, HTTP replay/proxy
- [ ] Fix suggestions in the report
- [x] A packaged GitHub Action — `uses: dugu0011/proofmark@v1`
- [x] Recon: crawl, extract forms/params, probe common paths
- [x] Intercept proxy: capture / mutate / replay requests
- [x] Signed, verifiable, replayable run records
- [x] Verified autofix — the agent writes the patch, Proofmark checks it applies
- [x] Spec inputs — OpenAPI / Swagger and Postman collections seed the endpoint map
- [x] Headless browser (XSS/CSRF/DOM) — run `proofmark build-sandbox` once to enable
- [x] A graph of agents (recon → exploit) — `--strategy graph`

## Design

- `cli.py` — the command line
- `agent.py` — the plan→act→observe loop and its budgets
- `tools/` — what the agent can do (each declares a schema, runs in the sandbox)
- `sandbox.py` — the Docker jail everything runs in
- `authorization.py` — the scope gate, enforced in code
- `llm.py` — one provider-agnostic call, via litellm
- `report.py` — the Markdown output

Rename the whole product by editing the three names in `proofmark/__about__.py`.

## License

MIT.
