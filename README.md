<div align="center">

<img src="assets/proofmark-banner.svg" alt="Proofmark — the AI pentester that proves what it finds" width="840" />

<h3>The open-source AI pentester that <em>proves</em> what it finds</h3>

<p><b>Autonomous agents that run your app in a sandbox, exploit it, and validate every finding with a reproduced proof-of-concept</b> — never a false positive from a static scanner.</p>

<p>
  <img alt="version" src="https://img.shields.io/badge/version-0.11.0-4f8cff?style=flat-square" />
  <img alt="license" src="https://img.shields.io/badge/license-MIT-7c5cff?style=flat-square" />
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-4f8cff?style=flat-square" />
  <img alt="tests" src="https://img.shields.io/badge/tests-157%20passing-22c55e?style=flat-square" />
  <img alt="providers" src="https://img.shields.io/badge/LLM-OpenAI%20%C2%B7%20Anthropic%20%C2%B7%20Azure-22d3ee?style=flat-square" />
  <img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-7c5cff?style=flat-square" />
</p>

<p>
  <a href="#setup--your-first-scan"><b>Setup</b></a> &nbsp;·&nbsp;
  <a href="#features"><b>Features</b></a> &nbsp;·&nbsp;
  <a href="#trust--safety"><b>Trust &amp; safety</b></a> &nbsp;·&nbsp;
  <a href="#usage"><b>Usage</b></a> &nbsp;·&nbsp;
  <a href="#how-it-works"><b>How it works</b></a>
</p>

</div>

> **⚖️ Authorized use only.** Proofmark actively exploits the targets you point it
> at. Only run it against systems you own or have explicit, written permission to
> test. It refuses to start without an explicit `--authorized` assertion, records
> that assertion in every run, and refuses any request outside the scope you gave
> it — but the responsibility for having permission is yours.

---

<div align="center">

**Proof, not suspicion** &nbsp;•&nbsp; **Safe against production** &nbsp;•&nbsp; **Signed & replayable** &nbsp;•&nbsp; **Injection-resistant** &nbsp;•&nbsp; **Priced per run**

</div>

## Overview

Proofmark is an autonomous penetration-testing agent that acts like a real
attacker: it runs your code dynamically inside an isolated Docker sandbox, forms
a hypothesis, and **reproduces the exploit** before it reports anything. Every
finding carries the request it sent and the response that proves the impact. If
it can't prove it, it doesn't report it.

It is built for developers and security teams who want fast, accurate testing
without the overhead of a manual pentest or the noise of a static scanner — and
it is built to be **trustworthy enough to actually run**: enforced scope, and a
signed, replayable record of everything the agent did.

**Key capabilities**

- **Prove, don't guess** — findings are validated with a working proof-of-concept, not pattern-matched.
- **Full offensive toolkit** — recon, OSINT, an HTTP intercept proxy, a real browser, a code reader, a shell, and a verified auto-fixer.
- **Multi-agent** — a recon agent maps the target, then an exploit agent proves what it can, sharing a blackboard.
- **Any target** — a live URL, a local codebase, a git repo, an OpenAPI/Swagger spec, or a Postman collection.
- **Enforced authorization** — scope is checked in code, not asked of the model. Out-of-scope requests are refused before they leave the process.
- **Signed, replayable run records** — every run is tamper-evident and can be re-verified and replayed. With a public-key (ed25519) signature, *anyone* can verify a report is authentic without your secret. *This is the part a security team needs before it will let an agent exploit its systems — and no other tool in this space has it.*
- **Safe against production** — safe mode blocks destructive HTTP methods (PUT/PATCH/DELETE), so the agent proves impact with reads, never by altering data.
- **Prompt-injection resistant** — everything the target returns is fenced as untrusted data, so a hostile page can't hijack the agent with "ignore previous instructions."
- **Earned confidence** — a live finding is only rated *high* after the exploit reproduces a second time via replay. One response is a claim; two is proof.
- **Split-brain models** — run recon on a fast, cheap model and exploitation on a stronger one, cutting cost and time without losing reasoning where it matters.
- **Per-run cost accounting** — every run reports exact tokens and an estimated dollar cost, written into the signed record so what a run cost is attested alongside what it proved.
- **Authenticated testing** — attach a token or session cookie and the agent tests as a logged-in user, where broken access control, IDOR and privilege-escalation bugs actually live.
- **Provider-agnostic** — OpenAI, Anthropic, Azure and more, via LiteLLM.

## Why Proofmark is different

Most tools in this space race to be the most *capable* generalist. Proofmark is
built to be the most *trustworthy* one:

| | Typical AI pentester | Proofmark |
|---|---|---|
| Authorization | a warning in the docs | **enforced in code**, recorded per run |
| Out-of-scope requests | trusted to the model | **refused before they send** |
| Run record | logs, at best | **hash-chained, optionally signed, replayable** |
| "Does the exploit still work?" | re-run and hope | **`proofmark replay`** |

## Setup & your first scan

**You need:** Python 3.10+ · Docker running · one LLM API key (Anthropic, OpenAI, or Azure).

**1 · Install**

```bash
pip install git+https://github.com/dugu0011/proofmark.git
```

**2 · Set your key** — pick your provider. The key you set and the `--model` you scan with must be the same provider:

| Provider | Set in your terminal | Scan flag |
|---|---|---|
| **Anthropic** | `export ANTHROPIC_API_KEY="sk-ant-..."` | *(none — it's the default)* |
| **OpenAI** | `export OPENAI_API_KEY="sk-..."` | `--model openai/gpt-4.1` |
| **Azure** | `export AZURE_API_KEY="..."`<br>`export AZURE_API_BASE="https://<resource>.openai.azure.com/"`<br>`export AZURE_API_VERSION="2024-12-01-preview"` | `--model azure/<deployment> --api-base "$AZURE_API_BASE"` |

Check it: `proofmark doctor` — it should print `✓ LLM key present: ...`.

**3 · Scan** — try it on a deliberately vulnerable app you run locally:

```bash
docker run -d --name juice -p 3001:3000 bkimminich/juice-shop
proofmark scan -t http://host.docker.internal:3001 --authorized --operator you --allow-host host.docker.internal
```

Using **Azure or OpenAI**? Add the `--model ...` from the table above to that scan line.
(The scan runs inside a sandbox, so target `host.docker.internal`, not `localhost`.)

**4 · Results** — proven findings print live; the full report and a replayable, tamper-evident record land in `proofmark_runs/<id>/`:

```bash
proofmark verify proofmark_runs/<id>    # is the record intact?
proofmark replay proofmark_runs/<id>    # does the exploit still work?
```

> ⚠️ Only scan what you own or have written permission to test — `--authorized` records that you do.
> Then point Proofmark at your own target the same way: a URL, git repo, local path, or OpenAPI/Postman file.
> Testing a single-page app or XSS? Run `proofmark build-sandbox` once to add the headless browser.

### Troubleshooting

| You see | Fix |
|---|---|
| `needs ANTHROPIC_API_KEY` — but you use Azure/OpenAI | Add the `--model` that matches your key, e.g. `--model azure/<deployment>`. Without it, Proofmark uses its Anthropic default. |
| `bind: address already in use` | That port is taken. Use another, e.g. `-p 3002:3000`, and scan `http://host.docker.internal:3002`. |
| `zsh: parse error near ')'` | You pasted a `# comment` line — zsh runs it as code. Paste only the commands (or run `setopt interactive_comments` once). |
| The scan can't reach your app | For a locally-hosted target use `host.docker.internal` (not `localhost`) and add `--allow-host host.docker.internal`. |
| `browser is unavailable` (XSS) | Run `proofmark build-sandbox` once, then retry. |
| `LiteLLM:WARNING ... model cost map` | Harmless — a pricing lookup only; the scan is unaffected. |

## Every run is signed, verifiable, and replayable

This is Proofmark's core difference. Each scan writes a **tamper-evident record**
to disk: what was authorized, every step the agent took, every request it sent,
and every finding it proved — with the steps hash-chained, so any later edit is
provable.

```bash
proofmark verify proofmark_runs/20260101-120000    # is this record intact?
proofmark replay proofmark_runs/20260101-120000    # does the exploit still work?

export PROOFMARK_SIGNING_KEY="..."                 # HMAC-sign records — now attributable, not just unaltered
```

## What a run looks like

A scan streams its reasoning and every request live, then writes a signed report.
Against a vulnerable target it **proves** findings; against a hardened one it honestly
reports nothing (a clean run is evidence, not proof of absence).

**A run that finds bugs** — OWASP Juice Shop (example):

```text
$ proofmark scan -t http://host.docker.internal:3001 --authorized --operator you --allow-host host.docker.internal

Proofmark v0.11.0  ·  target http://host.docker.internal:3001 (url)
authorized by you · scope: host.docker.internal · model anthropic/claude-sonnet-4-6
starting sandbox…
─ agent working ─
  → recon {"url":"http://host.docker.internal:3001","probe_paths":true}
  ← Mapped 12 page(s), 63 link(s), 4 form(s).
  → sql_injection_test {"url":".../rest/products/search?q=apple","param":"q"}
  ← SQL INJECTION LIKELY on 'q' (high). ERROR-BASED — payload "apple'" triggered a DB error.
  → http_request {...}                       # reproduces the exploit
  ← record_finding: SQL injection in product search
  ✓ 2 proven finding(s) in 24 step(s).
  41,203 tokens · ~$0.08
run record (verifiable) → proofmark_runs/20260831-120000
```

The report (`proofmark_runs/<id>/report.md`) lists each proven finding with its
proof-of-concept and fix:

```markdown
### 1. SQL injection in product search (critical)
- Location: GET /rest/products/search?q=
- OWASP A03:2021 Injection · CWE-89
- Proof: `q=apple'` returned a SQLite error; `q=apple'))--` dumped all product rows.
- Fix: use parameterized queries — never build SQL by concatenating input.
```

**A clean run** — a static, WAF-protected site honestly reports nothing:

```text
  ✓ Reconnaissance shows a static, read-only site; sensitive paths return 403
    (platform WAF). No attack surface exposed.
  0 proven finding(s) in 6 step(s).
```

That is the *expected* result when nothing exploitable is reachable — it means the
agent could not prove an exploit, not that none exists. To test an app that sits
behind a WAF, scan its **local instance** or its **source code** (see [Usage](#usage--what-you-can-test)).

## Features

### Agentic toolkit

Proofmark's agents drive the same tools a professional tester would, each running
inside the sandbox:

- **Recon** — crawl same-host links, extract forms and their parameters, probe common paths (`.env`, `.git`, admin, api).
- **Subdomain OSINT** — passive discovery from Certificate Transparency logs. Never probes what it finds; marks what is in scope.
- **HTTP intercept proxy** — send, list, and **replay** requests with any field mutated. The capture-mutate-replay loop that confirms injection and authorization bugs.
- **Browser** — a real headless Chromium for client-side bugs (reflected/stored/DOM XSS, CSRF). A fired dialog is captured as proof injected script executed.
- **Code analysis** — list, read and search the source of a code target, confined to the source root.
- **Shell + Python** — run commands inside the sandbox for exploit development and validation.
- **Verified auto-fix** — the agent writes a patch; Proofmark applies it in memory and accepts it *only if it applies cleanly*. A broken fix never reaches the report.

### Proving blind bugs — out-of-band confirmation

The worst bugs are blind: the response looks normal, but the target reaches back to a server
you control. Proofmark ships a built-in **out-of-band listener** that mints unique canary URLs
and records any callback — so blind SSRF, blind command injection, XXE exfiltration and blind
SQL injection are *confirmed*, not guessed. Self-contained; no external collaborator service.

### Dedicated exploit tools

Beyond the generic HTTP/browser loop, Proofmark drives deterministic, per-class tools that
detect and confirm mechanically — the reliable checks a freeform agent does inconsistently:

| Tool | Proves |
|---|---|
| `sql_injection_test` | SQLi — error, boolean, and time-based |
| `command_injection_test` | OS command injection / RCE — OOB, `id` output, `sleep` timing |
| `ssrf_test` | SSRF — OOB canary + cloud-metadata / file reads |
| `xxe_test` | XXE — OOB exfiltration + in-band file read |
| `ssti_test` | Template injection — arithmetic eval + engine fingerprint |
| `path_traversal_test` | LFI / path traversal — file-content signatures |
| `open_redirect_test` | Open redirect — OOB-followed canary |
| `jwt_attack_test` | JWT — alg=none forgery + weak-secret cracking |
| `graphql_test` | GraphQL — introspection + sensitive-operation surfacing |
| `xss_test` | XSS — real execution proof (a fired browser dialog) |
| `coverage` | Systematic OWASP-Top-10 coverage tracking per endpoint |

### Vulnerability classes

Broken access control (IDOR, privilege escalation, auth bypass) · injection (SQL,
NoSQL, command, SSTI) · server-side (SSRF, XXE, deserialization, RCE) ·
client-side (XSS, CSRF, prototype pollution) · authentication & session · security
misconfiguration · exposed secrets · API security (mass assignment, broken authz).

### Graph of agents

`--strategy graph` runs a coordinated team instead of one generalist: a **recon
agent** maps the target and is told explicitly *not* to exploit — it records what
it finds — then an **exploit agent** starts from that map and proves what it can.
Findings from every phase aggregate, and the authorization gate and signed record
wrap the whole graph.

### Measuring it — and comparing to other agents

`benchmarks/score.py` scores a run's **recall** over a target's known bug classes.
`benchmarks/compare.py` puts Proofmark **head to head** with another agent (e.g. Strix) on the
same target, reporting recall *and* the **proven-finding count** — because a finding you can't
reproduce shouldn't count the same as one you can. See [`benchmarks/README.md`](benchmarks/README.md).

```
Proofmark vs Strix — OWASP Juice Shop
  Proofmark    findings 3 | proven 3 | recall 0.33 | matched A01, A03
  Strix        findings 2 | proven 0 | recall 0.33 | matched A03, A05
  proven-finding edge: Proofmark 3 vs Strix 0 (Proofmark)
```

## Trust & safety

Proofmark is built to be pointed at real systems and believed:

- **Public-key signatures.** Generate a keypair with `proofmark keygen`, set `PROOFMARK_SIGNING_PRIVATE_KEY` to sign runs, and publish `PROOFMARK_SIGNING_PUBLIC_KEY`. Signed records embed the public key, so `proofmark verify <run>` confirms integrity with **no secret** — and pinning the public key also asserts *who* signed it.
- **Safe mode (default on).** Destructive methods are refused before they leave the process. Pass `--no-safe-mode` only when a state-changing test is genuinely required and authorized.
- **Untrusted-data fencing.** Target responses are wrapped in explicit markers and the agent is told they are data, never instructions — defusing prompt injection served by a hostile target.
- **Replay-gated confidence.** `high` confidence on a live target requires the exploit to reproduce on replay; otherwise it is recorded as `medium`.

```bash
proofmark keygen                                  # make a signing keypair
export PROOFMARK_SIGNING_PRIVATE_KEY=...           # sign every run
proofmark scan -t https://app.you.own --authorized --strategy graph \
  --recon-model openai/gpt-4o-mini --exploit-model anthropic/claude-opus-4-1
proofmark verify proofmark_runs/<run-id>           # anyone can verify, no secret
```

## Usage — what you can test

Point `-t` at any of these. **Local or hosted, a running app or source code** — all are first-class:

| Scenario | Command |
|---|---|
| **App running on your own machine** | `proofmark scan -t http://host.docker.internal:PORT --authorized --allow-host host.docker.internal` |
| **Hosted / remote URL** (staging, prod you own) | `proofmark scan -t https://your-app.com --authorized` |
| **Local source folder** — read *and run* to prove bugs | `proofmark scan -t ./my-service --authorized` |
| **Git repository** | `proofmark scan -t owner/repo --authorized` |
| **OpenAPI / Swagger spec** | `proofmark scan -t ./openapi.yaml --base-url https://api.your-app.com --authorized` |
| **Postman collection** | `proofmark scan -t ./collection.json --base-url https://api.your-app.com --authorized` |

> **Testing a local app** on macOS / Windows Docker Desktop? Use **`host.docker.internal:PORT`**,
> not `localhost` — the scan runs inside a sandbox container — and add `--allow-host host.docker.internal`.
> (On Linux, use your Docker gateway IP, often `172.17.0.1`.)

Add any of these to a scan:

```bash
# Go deeper: recon maps the surface, exploit proves it (multi-agent)
proofmark scan -t https://your-app.com --authorized --strategy graph --max-steps 60

# Authenticated: test as a logged-in user (reaches access-control bugs)
proofmark scan -t https://your-app.com --authorized --auth-header "Authorization: Bearer <token>"

# Broken access control between two users (BOLA / BFLA): give it a second identity
proofmark scan -t https://your-app.com --authorized --auth-header "Authorization: Bearer <user-A>" --second-auth-header "Authorization: Bearer <user-B>"

# Save the report to a file (exit code is non-zero if anything is proven — good for CI)
proofmark scan -t https://your-app.com --authorized -o report.md
```

## CI/CD (GitHub Actions)

Proofmark ships a packaged action — gate pull requests with a few lines:

```yaml
name: proofmark

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dugu0011/proofmark@v1
        with:
          target: ${{ vars.PREVIEW_URL }}   # a deployed preview you own
          authorized: "true"
          strategy: graph
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The job fails if a vulnerability is proven (configurable via `fail-on-findings`),
and the report is uploaded as an artifact.

## Use Proofmark from your coding agent

Proofmark is agent-ready. It ships a `SKILL.md` and an MCP server, so Claude Code,
Cursor, Codex or anything that speaks the Model Context Protocol can run a scan
and check a run record:

```bash
pip install "proofmark[mcp]"
proofmark mcp        # start the MCP server on stdio
```

## Configuration

Proofmark uses [LiteLLM](https://github.com/BerriAI/litellm), so any supported
provider works — set the model and the matching key:

```bash
export ANTHROPIC_API_KEY="..."     # for anthropic/... models (default)
export OPENAI_API_KEY="..."        # for openai/... models
export AZURE_API_KEY="..."         # for azure/... models

proofmark scan -t <target> --authorized --model openai/gpt-4o
```

Recommended models: `anthropic/claude-sonnet-4-6`, `openai/gpt-4o`.

## How it works

- `cli.py` — the command line
- `agent.py` — the plan→act→observe loop and its budgets
- `orchestrator.py` — the graph of agents, sharing a blackboard
- `tools/` — everything an agent can do; each declares a schema and runs in the sandbox
- `sandbox.py` — the Docker jail everything runs in (caps dropped, no host mounts)
- `authorization.py` — the scope gate, enforced in code
- `audit.py` — signed, hash-chained, replayable run records
- `llm.py` — one provider-agnostic call, via LiteLLM

Rename the whole product by editing the three names in `proofmark/__about__.py`.

## Contributing

Contributions of code, tools, and docs are welcome — open an issue or a pull
request. Run the test suite with `pytest` (Docker-backed tests skip
automatically when Docker is unavailable).

## Acknowledgements

Proofmark builds on the work of open-source projects including
[LiteLLM](https://github.com/BerriAI/litellm),
[Playwright](https://github.com/microsoft/playwright), and
[Docker](https://www.docker.com/). Thanks to their maintainers.

## License

MIT — see [LICENSE](LICENSE).

---

> **Warning — authorized use only.** Proofmark actively tests the targets you
> point it at. Only run it against systems you own or have explicit, written
> permission to test, and stay within the agreed scope. Unauthorized testing is
> illegal in most jurisdictions. You alone are responsible for obtaining
> authorization and complying with the law. Proofmark is provided "as is", with no
> warranty or liability for misuse.
