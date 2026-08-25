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
)
from proofmark.http_client import HttpClient, RequestLog, Request
from proofmark import audit
from proofmark.source import prepare as prepare_source, SourceError
from proofmark.prompts import code_mode_note

# Simple ANSI colour without a hard dependency on rich for the skeleton.
C = {"dim": "\033[2m", "b": "\033[1m", "cyan": "\033[36m", "yellow": "\033[33m",
     "red": "\033[31m", "green": "\033[32m", "reset": "\033[0m"}


def _classify(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return "url"
    if Path(target).exists():
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
@click.option("--api-base", default="", help="Custom API base (e.g. Azure endpoint).")
@click.option("--allow-host", "allow_hosts", multiple=True, help="Extra host the agent may reach.")
@click.option("--max-steps", default=40, show_default=True, help="Hard cap on agent actions.")
@click.option("--time-budget", default=600, show_default=True, help="Wall-clock cap, seconds.")
@click.option("-o", "--output", default="", help="Also write the Markdown report here.")
@click.option("--run-dir", default=audit.RUNS_DIR, show_default=True, help="Where to save the tamper-evident run record.")
def scan(target, authorized, operator, model, api_base, allow_hosts, max_steps, time_budget, output, run_dir):
    """Run the agent against a target and report what it can prove."""
    cfg = RunConfig(
        target=target, kind=_classify(target), model=model, api_base=api_base,
        operator=operator, allow_hosts=list(allow_hosts), max_steps=max_steps,
        time_budget_seconds=time_budget, output_path=output,
    )

    if not authorized:
        _fail("Refused. This tool actively exploits its target, so it will not run without "
              "--authorized, asserting you have permission to test it. That assertion is "
              "recorded in the report.")

    missing = cfg.missing_key()
    if missing:
        _fail(f"The model '{model}' needs {missing} in your environment. Set it and retry.")

    steps: list[dict] = []
    def _record(event: Event) -> None:
        steps.append({"kind": event.kind, "text": event.text, "detail": event.detail})
        _render(event)

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
            if is_code:
                click.echo(f"{C['dim']}copying source into the jail…{C['reset']}")
                sandbox.copy_in(source.root)
                client = HttpClient(sandbox, auth, req_log)
                tools = [
                    ListFilesTool(sandbox), ReadFileTool(sandbox), SearchCodeTool(sandbox),
                    RunCommandTool(sandbox), ReconTool(client), HttpRequestTool(client),
                    ListRequestsTool(client), ReplayRequestTool(client), RecordFindingTool(),
                ]
                suffix = code_mode_note()
            else:
                client = HttpClient(sandbox, auth, req_log)
                tools = [
                    ReconTool(client), HttpRequestTool(client), ListRequestsTool(client),
                    ReplayRequestTool(client), RunCommandTool(sandbox), RecordFindingTool(),
                ]
                suffix = ""

            registry = build_registry(tools)
            agent = Agent(
                LLM(model, api_base=api_base), registry, auth,
                name=NAME, system_suffix=suffix,
                max_steps=max_steps, time_budget_seconds=time_budget, on_event=_record,
            )
            click.echo(f"{C['dim']}─ agent working ─{C['reset']}")
            started_at = datetime.now(timezone.utc).isoformat()
            outcome = agent.run(source.label if source else target, cfg.kind)
            finished_at = datetime.now(timezone.utc).isoformat()
    except SandboxError as exc:
        _fail(f"Sandbox error: {exc}")
    finally:
        if source is not None:
            source.dispose()

    report = to_markdown(outcome, auth, target=target, model=model, product=NAME)
    click.echo("")
    n = len(outcome.findings)
    colour = C["yellow"] if n else C["green"]
    click.echo(f"{colour}{C['b']}{n} proven finding(s){C['reset']} in {outcome.steps_used} step(s).")
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
    out_dir = audit.save(record, run_dir)
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    signed = "signed" if __import__("os").environ.get(audit.SIGNING_KEY_ENV) else "unsigned"
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

    sys.exit(0 if ok else 1)


def _fail(message: str) -> None:
    click.echo(f"{C['red']}✗ {message}{C['reset']}", err=True)
    sys.exit(2)


if __name__ == "__main__":
    main()
