"""The command-line entry point.

    proofmark -t https://my-app.test --authorized
    proofmark -t ./my-service --authorized          (code target — coming next)
    proofmark doctor                                 (check the environment)

Kept deliberately small: parse the request, assert authorization, run the agent,
write the report. The interesting behaviour is in agent.py and the tools.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from proofmark.__about__ import NAME, SLUG, TAGLINE, VERSION
from proofmark.agent import Agent, Event, build_registry
from proofmark.authorization import Authorization
from proofmark.config import DEFAULT_MODEL, RunConfig
from proofmark.llm import LLM
from proofmark.report import to_markdown
from proofmark.sandbox import Sandbox, SandboxError
from proofmark.tools import HttpRequestTool, RecordFindingTool, RunCommandTool

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
@click.option("-o", "--output", default="", help="Write the Markdown report here.")
def scan(target, authorized, operator, model, api_base, allow_hosts, max_steps, time_budget, output):
    """Run the agent against a target and report what it can prove."""
    cfg = RunConfig(
        target=target, kind=_classify(target), model=model, api_base=api_base,
        operator=operator, allow_hosts=list(allow_hosts), max_steps=max_steps,
        time_budget_seconds=time_budget, output_path=output,
    )

    if cfg.kind != "url":
        _fail(f"This early build tests live URLs only. Code targets ('{cfg.kind}') are the next "
              "increment. Point it at a running instance for now.")

    if not authorized:
        _fail("Refused. This tool actively exploits its target, so it will not run without "
              "--authorized, asserting you have permission to test it. That assertion is "
              "recorded in the report.")

    missing = cfg.missing_key()
    if missing:
        _fail(f"The model '{model}' needs {missing} in your environment. Set it and retry.")

    auth = Authorization.grant(target, operator or "unknown", cfg.allow_hosts)
    click.echo(f"{C['b']}{NAME}{C['reset']} v{VERSION}  {C['dim']}·{C['reset']}  target {C['cyan']}{target}{C['reset']}")
    click.echo(f"{C['dim']}authorized by {auth.operator} · scope: {', '.join(sorted(auth.allowed_hosts))} · model {model}{C['reset']}")
    click.echo(f"{C['dim']}starting sandbox…{C['reset']}")

    try:
        with Sandbox() as sandbox:
            registry = build_registry([
                HttpRequestTool(sandbox, auth),
                RunCommandTool(sandbox),
                RecordFindingTool(),
            ])
            agent = Agent(
                LLM(model, api_base=api_base), registry, auth,
                name=NAME, max_steps=max_steps, time_budget_seconds=time_budget,
                on_event=_render,
            )
            click.echo(f"{C['dim']}─ agent working ─{C['reset']}")
            outcome = agent.run(target, cfg.kind)
    except SandboxError as exc:
        _fail(f"Sandbox error: {exc}")

    report = to_markdown(outcome, auth, target=target, model=model, product=NAME)
    click.echo("")
    n = len(outcome.findings)
    colour = C["yellow"] if n else C["green"]
    click.echo(f"{colour}{C['b']}{n} proven finding(s){C['reset']} in {outcome.steps_used} step(s).")
    if output:
        Path(output).write_text(report, encoding="utf-8")
        click.echo(f"{C['dim']}report written to {output}{C['reset']}")
    else:
        click.echo("")
        click.echo(report)

    # Non-zero exit when something was found, so CI can gate on it.
    sys.exit(1 if n else 0)


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
