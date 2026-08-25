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

## Install

```bash
pip install -e .          # from a clone
proofmark doctor          # check Docker + your LLM key are ready
```

You need Docker running and an API key for your model of choice:

```bash
export ANTHROPIC_API_KEY=...      # for anthropic/… models (default)
# or OPENAI_API_KEY / AZURE_API_KEY
```

## Use

```bash
# Scan a live URL you own
proofmark scan -t https://staging.my-app.test --authorized --operator you@team.com

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

A ready-to-copy GitHub Actions workflow is in
[`.github/workflows/example-scan.yml`](.github/workflows/example-scan.yml). It runs
a scan against a deployed preview URL and fails the job if anything is proven.

## Status

Early. This build tests **live URLs**. On the roadmap, in order:

- [ ] Code targets: a local path and a git repo
- [ ] A richer tool suite: headless browser, HTTP replay/proxy, file reading
- [ ] Fix suggestions in the report
- [ ] A packaged GitHub Action (not just an example workflow)

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
