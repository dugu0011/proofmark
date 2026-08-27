"""The command-line entry point.

    proofmark -t https://my-app.test --authorized
    proofmark -t ./my-service --authorized          (code target — coming next)
    proofmark doctor                                 (check the environment)

Kept deliberately small: parse the request, assert authorization, run the agent,
write the report. The interesting behaviour is in agent.py and the tools.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from proofmark.__about__ import NAME, SLUG, TAGLINE, VERSION
from proofmark.agent import Agent, Event, build_registry
from proofmark.authorization import Authorization
from proofmark.config import DEFAULT_MODEL, RunConfig
from proofmark.llm import LLM
from proofmark.report import to_markdown
from proofmark.sandbox import Sandbox, SandboxError
from proofmark.tools import (
    HttpRequestTool, ListFilesTool, ListRequestsTool, ReadFileTool, ReconTool,
    RecordFindingTool, ReplayRequestTool, RunCommandTool, SearchCodeTool,
    ProposeFixTool, FixLog, BrowserTool, NoteTool, SubdomainTool,
)
from proofmark.blackboard import Blackboard
from proofmark.orchestrator import Coordinator, Phase, RECON_ROLE, EXPLOIT_ROLE
from proofmark.http_client import HttpClient, RequestLog, Request
from proofmark import audit, specs
from proofmark.source import prepare as prepare_source, SourceError
from proofmark.prompts import code_mode_note

# Simple ANSI colour without a hard dependency on rich for the skeleton.
C = {"dim": "\033[2m", "b": "\033[1m", "cyan": "\033[36m", "yellow": "\033[33m",
     "red": "\033[31m", "green": "\033[32m", "reset": "\033[0m"}


def _classify(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return "url"
    p = Path(target)
    if p.is_file() and p.suffix.lower() in (".json", ".yaml", ".yml"):
        return "spec"
    if p.exists():
        return "path"
    if target.endswith(".git") or target.count("/") == 1 or "github.com" in target:
        return "repo"
    return "url"


def _render(event: Event) -> None:
    icon = {"think": f"{C['dim']}···{C['reset']}", "action": f"{C['cyan']}→{C['reset']}",
            "observation": f"{C['dim']}←{C['reset']}", "finding": f"{C['yellow']}★{C['reset']}",
            "done": f"{C['green']}✓{C['reset']}", "error": f"{C['red']}✗{C['reset']}"}.get(event.kind, " ")
    if event.kind == "think":
        click.echo(f"  {icon} {C['dim']}{event.text}{C['reset']}")
    elif event.kind == "action":
        click.echo(f"  {icon} {C['b']}{event.text}{C['reset']} {C['dim']}{event.detail}{C['reset']}")
    elif event.kind == "finding":
        click.echo(f"  {icon} {C['yellow']}{event.text}{C['reset']} {C['dim']}{event.detail}{C['reset']}")
    else:
        click.echo(f"  {icon} {event.text}")


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(VERSION, prog_name=NAME)
@click.pass_context
def main(ctx: click.Context) -> None:
    f"""{NAME} — {TAGLINE}"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.option("-t", "--target", required=True, help="A live URL, a git repo, or a local path.")
@click.option("--authorized", is_flag=True, help="Assert you are authorized to test this target.")
@click.option("--operator", default="", help="Who is running this (recorded in the report).")
@click.option("--model", default=DEFAULT_MODEL, show_default=True, help="LLM, litellm-style.")
@click.option("--recon-model", default="", help="Model for the recon phase of --strategy graph (defaults to --model).")
@click.option("--exploit-model", default="", help="Model for the exploit phase of --strategy graph (defaults to --model).")
@click.option("--api-base", default="", help="Custom API base (e.g. Azure endpoint).")
@click.option("--allow-host", "allow_hosts", multiple=True, help="Extra host the agent may reach.")
@click.option("--base-url", default="", help="Base URL to test a spec target against (if the spec omits it).")
@click.option("--max-steps", default=40, show_default=True, help="Hard cap on agent actions.")
@click.option("--safe-mode/--no-safe-mode", default=True, show_default=True, help="Block destructive HTTP methods (PUT/PATCH/DELETE) so it is safe against production.")
@click.option("--strategy", type=click.Choice(["single", "graph"]), default="single", show_default=True, help="single agent, or a recon->exploit graph of agents.")
@click.option("--time-budget", default=600, show_default=True, help="Wall-clock cap, seconds.")
@click.option("-o", "--output", default="", help="Also write the Markdown report here.")
@click.option("--run-dir", default=audit.RUNS_DIR, show_default=True, help="Where to save the tamper-evident run record.")
@click.option("--events-file", default="", help="Append each agent event as JSONL here (live streaming).")
@click.option("--control-file", default="", help="Read operator steering instructions from here, one per line.")
def scan(target, authorized, operator, model, recon_model, exploit_model, api_base, allow_hosts, base_url, strategy, max_steps, safe_mode, time_budget, output, run_dir, events_file, control_file):
    """Run the agent against a target and report what it can prove."""
    cfg = RunConfig(
        target=target, kind=_classify(target), model=model,
        recon_model=recon_model, exploit_model=exploit_model, api_base=api_base,
        operator=operator, allow_hosts=list(allow_hosts), max_steps=max_steps,
        safe_mode=safe_mode, time_budget_seconds=time_budget, output_path=output,
    )

    if not authorized:
        _fail("Refused. This tool actively exploits its target, so it will not run without "
              "--authorized, asserting you have permission to test it. That assertion is "
              "recorded in the report.")

    missing = cfg.missing_key()
    if missing:
        _fail(f"The model '{model}' needs {missing} in your environment. Set it and retry.")

    import json as _json

    steps: list[dict] = []
    fix_log = FixLog()
    _events_fh = open(events_file, "a", encoding="utf-8") if events_file else None

    def _record(event: Event) -> None:
        steps.append({"kind": event.kind, "text": event.text, "detail": event.detail})
        if _events_fh is not None:
            # one JSON object per line, flushed, so a host can tail it live
            _events_fh.write(_json.dumps({
                "ts": __import__("time").time(), "kind": event.kind,
                "text": event.text, "detail": event.detail,
            }) + "\n")
            _events_fh.flush()
        _render(event)

    _control_pos = {"n": 0}

    def _pull_steer() -> list:
        """New operator instructions appended to the control file since last read."""
        if not control_file:
            return []
        try:
            with open(control_file, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return []
        new = lines[_control_pos["n"]:]
        _control_pos["n"] = len(lines)
        return [l for l in new if l.strip()]

    spec_briefing = ""
    if cfg.kind == "spec":
        try:
            text = Path(target).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _fail(f"could not read the spec: {exc}")
        kind = specs.sniff(text)
        if kind is None:
            _fail("that file is not a recognized OpenAPI/Swagger spec or Postman collection.")
        base, endpoints = specs.parse(text)
        base = base_url or base
        if not base:
            _fail("the spec has no server URL — pass --base-url https://api.you.own to say where to test.")
        if not endpoints:
            _fail("no endpoints found in the spec.")
        spec_briefing = specs.briefing(base, endpoints)
        click.echo(f"{C['dim']}spec: {len(endpoints)} endpoint(s) → testing against {base}{C['reset']}")
        # from here on it behaves like a URL target pointed at the spec's server
        target = base
        cfg.kind = "url"

    is_code = cfg.kind in ("path", "repo")
    if is_code:
        auth = Authorization.for_code(target, operator or "unknown")
    else:
        auth = Authorization.grant(target, operator or "unknown", cfg.allow_hosts)

    click.echo(f"{C['b']}{NAME}{C['reset']} v{VERSION}  {C['dim']}·{C['reset']}  target {C['cyan']}{target}{C['reset']} ({cfg.kind})")
    click.echo(f"{C['dim']}authorized by {auth.operator} · scope: {', '.join(sorted(auth.allowed_hosts))} · model {model}{C['reset']}")

    source = None
    if is_code:
        click.echo(f"{C['dim']}preparing source…{C['reset']}")
        try:
            source = prepare_source(target, cfg.kind)
        except SourceError as exc:
            _fail(str(exc))

    click.echo(f"{C['dim']}starting sandbox…{C['reset']}")
    try:
        with Sandbox() as sandbox:
            req_log = RequestLog()
            browser = BrowserTool(auth)
            if is_code:
                click.echo(f"{C['dim']}copying source into the jail…{C['reset']}")
                sandbox.copy_in(source.root)
                client = HttpClient(sandbox, auth, req_log, safe_mode=cfg.safe_mode)
                tools = [
                    ListFilesTool(sandbox), ReadFileTool(sandbox), SearchCodeTool(sandbox),
                    RunCommandTool(sandbox), ReconTool(client), HttpRequestTool(client),
                    ListRequestsTool(client), ReplayRequestTool(client),
                    ProposeFixTool(sandbox, fix_log), browser, RecordFindingTool(req_log, require_replay=not is_code),
                ]
                suffix = code_mode_note()
            else:
                client = HttpClient(sandbox, auth, req_log, safe_mode=cfg.safe_mode)
                tools = [
                    ReconTool(client), SubdomainTool(sandbox, auth), HttpRequestTool(client),
                    ListRequestsTool(client), ReplayRequestTool(client), RunCommandTool(sandbox),
                    browser, RecordFindingTool(req_log, require_replay=not is_code),
                ]
                suffix = spec_briefing

            llm = LLM(model, api_base=api_base)
            run_target = source.label if source else target
            started_at = datetime.now(timezone.utc).isoformat()
            recon_llm = LLM(cfg.recon_model, api_base=api_base) if cfg.recon_model else llm
            exploit_llm = LLM(cfg.exploit_model, api_base=api_base) if cfg.exploit_model else llm
            if strategy == "graph":
                if cfg.recon_model or cfg.exploit_model:
                    click.echo(f"{C['dim']}models: recon {recon_llm.model} · exploit {exploit_llm.model}{C['reset']}")
                click.echo(f"{C['dim']}─ graph of agents: recon → exploit ─{C['reset']}")
                blackboard = Blackboard()
                recon_tools = [
                    ReconTool(client), SubdomainTool(sandbox, auth), HttpRequestTool(client),
                    ListRequestsTool(client), RunCommandTool(sandbox), NoteTool(blackboard),
                ]
                if is_code:
                    recon_tools = [
                        ListFilesTool(sandbox), ReadFileTool(sandbox), SearchCodeTool(sandbox),
                        RunCommandTool(sandbox), ReconTool(client), HttpRequestTool(client),
                        NoteTool(blackboard),
                    ]
                exploit_tools = tools  # the full offensive set built above
                phases = [
                    Phase("recon", RECON_ROLE + ("\n\n" + suffix if suffix else ""),
                          recon_tools, max_steps=max(8, max_steps // 3), llm=recon_llm),
                    Phase("exploit", EXPLOIT_ROLE + ("\n\n" + suffix if suffix else ""),
                          exploit_tools, max_steps=max_steps, llm=exploit_llm),
                ]
                coordinator = Coordinator(
                    llm, auth, name=NAME, phases=phases, blackboard=blackboard,
                    time_budget_seconds=time_budget, on_event=_record, steer_fn=_pull_steer,
                )
                outcome = coordinator.run(run_target, cfg.kind)
            else:
                click.echo(f"{C['dim']}─ agent working ─{C['reset']}")
                agent = Agent(
                    llm, build_registry(tools), auth,
                    name=NAME, system_suffix=suffix,
                    max_steps=max_steps, time_budget_seconds=time_budget, on_event=_record,
                    steer_fn=_pull_steer,
                )
                outcome = agent.run(run_target, cfg.kind)
            finished_at = datetime.now(timezone.utc).isoformat()
            # What the run cost: sum the usage of every model it actually invoked.
            _llms = {id(llm): llm}
            for _l in (recon_llm, exploit_llm):
                _llms[id(_l)] = _l
            run_usage = _aggregate_usage(list(_llms.values()))
            browser.close()
    except SandboxError as exc:
        _fail(f"Sandbox error: {exc}")
    finally:
        if source is not None:
            source.dispose()

    if _events_fh is not None:
        _events_fh.close()

    report = to_markdown(outcome, auth, target=target, model=model, product=NAME, fixes=fix_log.fixes)
    click.echo("")
    n = len(outcome.findings)
    colour = C["yellow"] if n else C["green"]
    click.echo(f"{colour}{C['b']}{n} proven finding(s){C['reset']} in {outcome.steps_used} step(s).")
    if run_usage.get("total_tokens"):
        _cost = run_usage.get("cost_usd") or 0.0
        click.echo(f"{C['dim']}{run_usage['total_tokens']:,} tokens"
                   f"{f' · ~${_cost:.4f}' if _cost else ''}{C['reset']}")
    # The tamper-evident run record — always written. This is the point of
    # difference: a signed, replayable transcript of exactly what happened.
    record = audit.RunRecord(
        run_id=audit.new_run_id(), product=NAME, version=VERSION,
        target=target, kind=cfg.kind, operator=auth.operator, model=model,
        authorization=auth.as_header(), started_at=started_at, finished_at=finished_at,
        stopped_reason=outcome.stopped_reason, steps=steps, requests=req_log.records(),
        findings=[{
            "title": f.title, "severity": f.severity.value, "location": f.location,
            "description": f.description, "proof_of_concept": f.proof_of_concept,
            "remediation": f.remediation,
        } for f in outcome.findings],
    )
    record.fixes = fix_log.fixes
    record.usage = run_usage
    out_dir = audit.save(record, run_dir)
    for i, fx in enumerate(fix_log.fixes, 1):
        (out_dir / f"fix-{i}.patch").write_text(fx["diff"] + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    _env = __import__("os").environ
    if _env.get(audit.SIGNING_PRIVATE_ENV):
        signed = "ed25519-signed"
    elif _env.get(audit.SIGNING_KEY_ENV):
        signed = "hmac-signed"
    else:
        signed = "unsigned"
    click.echo(f"{C['dim']}run record ({signed}, verifiable) → {out_dir}{C['reset']}")
    if output:
        Path(output).write_text(report, encoding="utf-8")
        click.echo(f"{C['dim']}report also written to {output}{C['reset']}")
    else:
        click.echo("")
        click.echo(report)

    # Non-zero exit when something was found, so CI can gate on it.
    sys.exit(1 if n else 0)


@main.command()
@click.argument("run_dir")
def verify(run_dir):
    """Check that a run record is intact (and its signature, if signed)."""
    ok, reason = audit.verify(run_dir)
    mark = f"{C['green']}\u2713{C['reset']}" if ok else f"{C['red']}\u2717{C['reset']}"
    click.echo(f"{mark} {reason}")
    sys.exit(0 if ok else 1)


@main.command()
@click.argument("run_dir")
def replay(run_dir):
    """Re-issue a run's recorded requests and report whether they still reproduce.

    A run record is replayable because every request was captured. This starts a
    fresh sandbox, re-sends the in-scope requests, and compares the responses to
    what was recorded — the concrete check for "does this exploit still work?"
    """
    try:
        manifest = audit.load(run_dir)
    except (FileNotFoundError, ValueError) as exc:
        _fail(f"could not read the run record: {exc}")

    ok, reason = audit.verify(run_dir)
    if not ok:
        _fail(f"refusing to replay a record that does not verify: {reason}")
    click.echo(f"{C['dim']}record verified: {reason}{C['reset']}")

    scope = [h for h in manifest.get("authorization", {}).get("scope", [])
             if not h.startswith("(")]
    auth = Authorization(
        target=manifest.get("target", ""), operator=manifest.get("operator", "replay"),
        asserted_at=datetime.now(timezone.utc), allowed_hosts=frozenset(scope),
    )
    requests = [r for r in manifest.get("requests", []) if r.get("url") and r.get("status") is not None]
    if not requests:
        click.echo("No successful requests were recorded to replay.")
        sys.exit(0)

    click.echo(f"{C['dim']}replaying {len(requests)} request(s)…{C['reset']}")
    same = 0
    try:
        with Sandbox() as sandbox:
            client = HttpClient(sandbox, auth, RequestLog())
            for r in requests:
                ok_, _text, ex = client.send(Request(
                    r["method"], r["url"], r.get("headers") or {}, r.get("body")))
                match = ex.status == r.get("status")
                same += 1 if match else 0
                flag = f"{C['green']}=={C['reset']}" if match else f"{C['yellow']}!={C['reset']}"
                click.echo(f"  {flag} {r['method']} {r['url']}  was {r.get('status')} now {ex.status}")
    except SandboxError as exc:
        _fail(f"sandbox error: {exc}")

    click.echo(f"\n{same}/{len(requests)} request(s) reproduced the recorded response.")
    sys.exit(0)


@main.command(name="mcp")
def mcp_cmd():
    """Start the MCP server (stdio) so an AI assistant can run Proofmark."""
    from proofmark.mcp_server import main as mcp_main
    mcp_main()


@main.command(name="build-sandbox")
def build_sandbox():
    """Build the browser sandbox image (Chromium) used by the `browser` tool."""
    import subprocess
    import tempfile
    from pathlib import Path as _P

    # The Dockerfile is generated here rather than read from disk, so this works
    # from a pip install (where no repo files ship) exactly as from a checkout.
    dockerfile = (
        "FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy\n"
        "RUN pip install --no-cache-dir playwright==1.47.0\n"
        "WORKDIR /work\n"
        'CMD ["sleep", "infinity"]\n'
    )
    click.echo(f"{C['dim']}building proofmark-sandbox:latest (pulls Chromium; a few minutes)…{C['reset']}")
    with tempfile.TemporaryDirectory() as ctx:
        (_P(ctx) / "Dockerfile").write_text(dockerfile)
        try:
            subprocess.run(
                ["docker", "build", "-t", "proofmark-sandbox:latest", ctx],
                check=True,
            )
        except FileNotFoundError:
            _fail("docker is not installed or not on PATH.")
        except subprocess.CalledProcessError as exc:
            _fail(f"docker build failed (exit {exc.returncode}).")
    click.echo(f"{C['green']}\u2713{C['reset']} browser sandbox built. The `browser` tool is now available.")


@main.command()
def keygen():
    """Generate an ed25519 signing keypair for public-key run-record signatures.

    Set the private key as PROOFMARK_SIGNING_PRIVATE_KEY to sign runs; publish the
    public key so anyone can verify a report is authentic — without your secret.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        _fail("this needs the 'cryptography' package: pip install cryptography")
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    click.echo(f"{C['b']}Ed25519 signing keypair{C['reset']}")
    click.echo(f"{C['dim']}Keep the private key secret; publish the public key.{C['reset']}\n")
    click.echo(f"{C['yellow']}PROOFMARK_SIGNING_PRIVATE_KEY{C['reset']}={seed}")
    click.echo(f"{C['green']}PROOFMARK_SIGNING_PUBLIC_KEY{C['reset']}=ed25519:{pub}")
    click.echo(f"\n{C['dim']}Signed runs embed the public key, so `proofmark verify <run>` "
               f"checks integrity with no secret. Pin PROOFMARK_SIGNING_PUBLIC_KEY to also "
               f"assert the signer's identity.{C['reset']}")
    sys.exit(0)


@main.command()
def doctor():
    """Check that Docker and an LLM key are available."""
    ok = True
    try:
        import docker
        docker.from_env().ping()
        click.echo(f"{C['green']}✓{C['reset']} Docker is reachable")
    except Exception as exc:  # noqa: BLE001
        ok = False
        click.echo(f"{C['red']}✗{C['reset']} Docker: {exc}")

    import os
    keys = [v for v in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_API_KEY") if os.environ.get(v)]
    if keys:
        click.echo(f"{C['green']}✓{C['reset']} LLM key present: {', '.join(keys)}")
    else:
        ok = False
        click.echo(f"{C['red']}✗{C['reset']} No LLM key set (ANTHROPIC_API_KEY / OPENAI_API_KEY / AZURE_API_KEY)")

    try:
        import litellm  # noqa: F401
        click.echo(f"{C['green']}✓{C['reset']} litellm installed")
    except ImportError:
        ok = False
        click.echo(f"{C['red']}✗{C['reset']} litellm not installed (pip install litellm)")

    try:
        import docker as _d
        _d.from_env().images.get("proofmark-sandbox:latest")
        click.echo(f"{C['green']}✓{C['reset']} browser sandbox image built")
    except Exception:  # noqa: BLE001
        click.echo(f"{C['dim']}○ browser sandbox not built (optional) — run: proofmark build-sandbox{C['reset']}")

    sys.exit(0 if ok else 1)


def _aggregate_usage(llms) -> dict:
    """Sum token usage and estimated cost across the models a run used."""
    total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
             "cost_usd": 0.0, "calls": 0, "by_model": {}}
    for llm in llms:
        u = llm.usage()
        total["prompt_tokens"] += u["prompt_tokens"]
        total["completion_tokens"] += u["completion_tokens"]
        total["total_tokens"] += u["total_tokens"]
        total["cost_usd"] += u["cost_usd"]
        total["calls"] += u["calls"]
        if u["calls"]:
            # a run may use one model for two phases — merge, do not overwrite
            m = total["by_model"].setdefault(
                u["model"], {"calls": 0, "total_tokens": 0, "cost_usd": 0.0})
            m["calls"] += u["calls"]
            m["total_tokens"] += u["total_tokens"]
            m["cost_usd"] = round(m["cost_usd"] + u["cost_usd"], 6)
    total["cost_usd"] = round(total["cost_usd"], 6)
    return total


def _fail(message: str) -> None:
    click.echo(f"{C['red']}✗ {message}{C['reset']}", err=True)
    sys.exit(2)


if __name__ == "__main__":
    main()
