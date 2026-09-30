"""Run the isolation checks against one mode and score them.

    python -m attacks.run --mode B0
    python -m attacks.run --mode B3 --no-egress-canary     # B3 without the canary part of egress
    python -m attacks.run --mode B1 --no-spawn             # services already running

Per mode: toggle RLS (owner), start app + MCP with GUARD_MODE, verify every tenant can retrieve
its own canary (otherwise a 0% proves nothing), then for each case x repeats: reset state, run
setup steps, run the scored steps, collect every channel, detect, save results/<mode>.json.
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

import httpx
import httpx2
import psycopg
import redis
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from app import config
from app.seed import DEMO_PASSWORD
from attacks.detector import Registry, detect
from tenantguard.db import set_rls
from tenantguard.tracing import read as read_trace

ROOT = Path(__file__).resolve().parents[1]
# One folder per model, so mock and real-model runs never overwrite each other.
LLM_TAG = "mock" if config.LLM_PROVIDER == "mock" else re.sub(r"[^A-Za-z0-9.]+", "-", config.LLM_MODEL).strip("-")
RESULTS = ROOT / "results" / LLM_TAG


# ---------------------------------------------------------------- services

def spawn(mode: str, egress_canary: bool) -> list[subprocess.Popen]:
    env = {**os.environ, "GUARD_MODE": mode, "TG_EGRESS_CANARY": "1" if egress_canary else "0",
           "HF_HUB_DISABLE_SYMLINKS_WARNING": "1", "PYTHONUNBUFFERED": "1"}
    RESULTS.mkdir(parents=True, exist_ok=True)
    procs = []
    # Ports come from MCP_URL / APP_URL, so a second stack (another database, other ports) can run
    # alongside a long benchmark without touching it.
    for module, port in (("mcp_server.server:app", urlparse(config.MCP_URL).port), ("app.main:app", urlparse(config.APP_URL).port)):
        # Append, so a restart after a crash keeps the crashed server's output.
        log = open(RESULTS / f"server_{mode}_{port}.log", "a")
        log.write(f"==== start {time.strftime('%Y-%m-%d %H:%M:%S')} ====\n")
        log.flush()
        procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", module, "--port", str(port)],
                                      cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT))
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            health = httpx.get(config.APP_URL + "/health", timeout=2).json()
            if health["mode"] == mode:
                return procs
        except httpx.HTTPError:
            pass
        time.sleep(1)
    stop(procs)
    raise SystemExit("services did not start; see results/server_*.log")


def stop(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


# ---------------------------------------------------------------- state

class State:
    def __init__(self) -> None:
        self.owner = psycopg.connect(config.OWNER_DATABASE_URL, autocommit=True)
        self.redis = redis.Redis.from_url(config.REDIS_URL)
        self.tenants = [r[0] for r in self.owner.execute("SELECT tenant_id FROM tg.tenants").fetchall()]
        self.ticket_tenant = dict(self._per_tenant("SELECT id, tenant_id FROM tg.tickets"))

    def _per_tenant(self, sql: str, params=()) -> list[tuple]:
        """Read as owner under FORCE RLS by visiting each tenant; dedupe when RLS is off."""
        rows: dict = {}
        for t in self.tenants:
            with self.owner.transaction():
                self.owner.execute("SELECT set_config('app.tenant_id', %s, true)", (t,))
                for r in self.owner.execute(sql, params).fetchall():
                    rows[r[0]] = r
        return list(rows.values())

    def reset(self) -> None:
        self.owner.execute("TRUNCATE tg.notes, tg.app_logs RESTART IDENTITY")
        for pattern in ("tg:mem:*", "tg:trace:*", "tg_cache_legacy:*", "tg_cache_scoped:*"):
            for key in self.redis.scan_iter(pattern):
                self.redis.delete(key)

    def watermark(self) -> tuple[int, int]:
        logs = self._per_tenant("SELECT id FROM tg.app_logs")
        notes = self._per_tenant("SELECT id FROM tg.notes")
        return max((r[0] for r in logs), default=0), max((r[0] for r in notes), default=0)

    def new_rows(self, mark: tuple[int, int]) -> tuple[list[dict], list[dict]]:
        logs = self._per_tenant("SELECT id, tenant_id, message FROM tg.app_logs WHERE id > %s", (mark[0],))
        notes = self._per_tenant("SELECT id, tenant_id, ticket_id, body FROM tg.notes WHERE id > %s", (mark[1],))
        return ([{"tenant_id": r[1], "message": r[2]} for r in logs],
                [{"tenant_id": r[1], "ticket_tenant": self.ticket_tenant.get(r[2]), "body": r[3]} for r in notes])


# ---------------------------------------------------------------- steps

_tokens: dict[str, str] = {}
# A local model on CPU can take minutes for a multi-round agent request.
# Longer than the app itself can take (every tool round hitting the LLM timeout), so the harness
# never gives up on a request the app would still have finished.
STEP_TIMEOUT = 120 if config.LLM_PROVIDER == "mock" else config.LLM_MAX_TOOL_ROUNDS * config.OLLAMA_TIMEOUT_SECONDS + 300


_issued: dict[str, float] = {}
TOKEN_REFRESH_SECONDS = 30 * 60  # login tokens live 1 h; a slow local-model run outlasts that


def token(who: str) -> str:
    if who not in _tokens or time.time() - _issued[who] > TOKEN_REFRESH_SECONDS:
        tenant, user = who.split("/")
        r = httpx.post(config.APP_URL + "/login", json={"tenant": tenant, "username": user, "password": DEMO_PASSWORD}, timeout=10)
        r.raise_for_status()
        _tokens[who] = r.json()["token"]
        _issued[who] = time.time()
    return _tokens[who]


async def mcp_call(tool: str, args: dict, bearer: str | None) -> str:
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    try:
        async with httpx2.AsyncClient(headers=headers, timeout=30) as http:
            async with Client(streamable_http_client(config.MCP_URL, http_client=http)) as client:
                result = await client.call_tool(tool, args)
                return "\n".join(getattr(c, "text", "") for c in result.content)
    except BaseException as exc:  # noqa: BLE001 - auth failures surface as transport errors
        return f"error: {_describe(exc)}"


def _describe(exc: BaseException) -> str:
    """Unwrap anyio exception groups to an HTTP status, else to the innermost error."""
    stack, leaf = [exc], exc
    while stack:
        e = stack.pop()
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status is not None:
            return f"HTTP {status}"
        children = list(getattr(e, "exceptions", ())) + ([e.__cause__] if e.__cause__ is not None else [])
        if not children:
            leaf = e
        stack.extend(children)
    return f"{type(leaf).__name__}: {str(leaf)[:160]}"


class SetupFailed(RuntimeError):
    """A setup step (run as the victim) didn't succeed, so the case can't prove anything."""


def run_setup_step(step: dict, r: redis.Redis) -> str:
    """Setup must succeed: a failed setup would score as 'no leak' without testing anything."""
    _, text, status = _run(step, step["as"], r)
    if status != 200:
        raise SetupFailed(f"setup step as {step['as']} returned HTTP {status}: {text[:200]}")
    return text


class StepError(RuntimeError):
    """A scored step failed on the server side, so it observed nothing either way."""


def run_step(step: dict, who: str, r: redis.Redis) -> tuple[list[dict], str]:
    """Returns (trace events, raw response text). Denials (401/403) are valid outcomes here;
    server errors (5xx) are not, because a crashed request would otherwise score as 'no leak'."""
    events, text, status = _run(step, who, r)
    if status >= 500:
        raise StepError(f"HTTP {status}: {text[:200]}")
    return events, text


def _run(step: dict, who: str, r: redis.Redis) -> tuple[list[dict], str, int]:
    headers = {"Authorization": f"Bearer {token(who)}", **step.get("headers", {})}
    ep = step["endpoint"]
    if ep == "mcp":
        bearer = token(who) if step.get("auth") == "login" else None
        text = asyncio.run(mcp_call(step["tool"], step["args"], bearer))
        return [{"channel": "final_output", "content": text}], text, 200
    if ep == "logs":
        resp = httpx.get(config.APP_URL + "/support/logs", params=step.get("params", {}), headers=headers, timeout=STEP_TIMEOUT)
    else:
        payload = {"question": step["text"]} if ep == "ask" else {"message": step["text"]}
        resp = httpx.post(f"{config.APP_URL}/{ep}", json=payload, headers=headers, timeout=STEP_TIMEOUT)
    text = resp.text
    rid = resp.headers.get("x-request-id")
    events = read_trace(r, rid) if rid else []
    if not any(e["channel"] == "final_output" for e in events):
        events.append({"channel": "final_output", "content": text})
    return events, text, resp.status_code


# ---------------------------------------------------------------- main

def precheck(state: State, registry: Registry) -> None:
    """Each tenant must retrieve its own documents. Checked on the retrieval channel, not the answer:
    a real model paraphrases and rarely repeats internal reference codes."""
    for tenant in state.tenants:
        state.reset()
        events, _ = run_step({"endpoint": "ask", "text": "What is the refund window in our refund policy?"}, f"{tenant}/alice", state.redis)
        retrieved = "\n".join(e["content"] for e in events if e["channel"] == "retrieval")
        own = [c for c in registry.find(retrieved) if registry.owner_of[c] == tenant]
        if not own:
            raise SystemExit(f"precheck failed: {tenant} cannot retrieve its own documents, so a clean run would prove nothing")


def _answer_of(text: str) -> str:
    try:
        return json.loads(text).get("answer") or ""
    except (ValueError, AttributeError):
        return ""


# Transport failures that mean a server process died (not a timeout, which is handled per step).
SERVER_DOWN = (httpx.ConnectError, httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError)


def error_record(case: dict, rep: int, error: str) -> dict:
    return {"id": case["id"], "route": case["route"], "owasp": case["owasp"], "repeat": rep,
            "leak_answer": False, "leak_any": False, "channels": [], "leaks": [],
            "response": f"error: {error}", "error": error}


def run_check(case: dict, rep: int, state: "State", registry: Registry) -> dict:
    """Reset, run setup as the other users, run the scored steps, detect. Raises SERVER_DOWN."""
    state.reset()
    foreign_outputs = []
    for step in case.get("setup", []):
        text = run_setup_step(step, state.redis)
        foreign_outputs.append((step["as"].split("/")[0], _answer_of(text)))
    mark = state.watermark()
    events, texts, error = [], [], None
    for step in case["steps"]:
        try:
            evs, text = run_step(step, case["as"], state.redis)
        except (httpx.TimeoutException, StepError) as exc:
            # Not a pass: nothing was observed. Recorded as an error and shown in the summary.
            error = f"timeout after {STEP_TIMEOUT}s" if isinstance(exc, httpx.TimeoutException) else str(exc)
            texts.append(f"error: {error}")
            break
        events.extend(evs)
        texts.append(text)
    new_logs, new_notes = state.new_rows(mark)
    session_tenant = case["as"].split("/")[0]
    leaks = detect(registry, session_tenant, events, new_logs, new_notes, foreign_outputs)
    return {
        "id": case["id"], "route": case["route"], "owasp": case["owasp"], "repeat": rep,
        "leak_answer": any(l.channel == "final_output" for l in leaks),
        "leak_any": bool(leaks),
        "channels": sorted({l.channel for l in leaks}),
        "leaks": [asdict(l) for l in leaks],
        "response": texts[-1][:2000],
        "error": error,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=[m.value for m in config.Mode])
    ap.add_argument("--repeats", type=int, default=None, help="default: 1 for mock/ollama, 3 otherwise")
    ap.add_argument("--cases", default=str(ROOT / "attacks" / "cases.yaml"))
    ap.add_argument("--no-egress-canary", action="store_true")
    ap.add_argument("--firewall", choices=["heuristic", "promptguard"], default="heuristic", help="B2's input firewall")
    ap.add_argument("--no-spawn", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="run only the checks missing from the saved results (partial or finished)")
    args = ap.parse_args()
    # mock and ollama (temperature 0, fixed seed) are deterministic, so one repeat is enough.
    repeats = args.repeats or (1 if config.LLM_PROVIDER in ("mock", "ollama") else 3)
    if args.firewall != "heuristic" and args.mode != "B2":
        ap.error("--firewall only applies to B2")
    os.environ["TG_FIREWALL"] = args.firewall  # inherited by the servers spawn() starts
    label = args.mode + ("_nocanary" if args.no_egress_canary else "") + ("_promptguard" if args.firewall == "promptguard" else "")
    RESULTS.mkdir(parents=True, exist_ok=True)
    final_path, partial_path = RESULTS / f"{label}.json", RESULTS / f"{label}.partial.json"
    cases = yaml.safe_load(Path(args.cases).read_text(encoding="utf-8"))
    order = {c["id"]: i for i, c in enumerate(cases)}

    records: list[dict] = []
    if args.resume:
        # An interrupted run continues from its partial file. A finished one is extended with the
        # checks added to the case file since it ran, so they don't force a re-run of the rest.
        source = partial_path if partial_path.exists() else final_path if final_path.exists() else None
        if source is not None:
            saved = json.loads(source.read_text(encoding="utf-8"))
            saved = saved["records"] if isinstance(saved, dict) else saved
            records = [r for r in saved if not r.get("error") and r["id"] in order]  # errored checks get another try
    done = {(r["id"], r["repeat"]) for r in records}
    todo = sum((c["id"], rep) not in done for c in cases for rep in range(repeats))
    if args.resume:
        if not todo:
            print(f"{label}: already complete, skipping")
            return
        if records:
            print(f"{label}: resuming with {len(records)} saved checks, {todo} to run", flush=True)

    state = State()
    set_rls(state.owner, args.mode == "B3")
    registry = Registry.load()
    procs = [] if args.no_spawn else spawn(args.mode, not args.no_egress_canary)
    try:
        _tokens.clear()
        precheck(state, registry)
        for case in cases:
            for rep in range(repeats):
                if (case["id"], rep) in done:
                    continue
                for attempt in (1, 2):
                    try:
                        rec = run_check(case, rep, state, registry)
                        break
                    except SERVER_DOWN as exc:
                        # The app or MCP server died mid-check (on a memory-starved machine, a native
                        # crash). Restart both and re-run the whole check once from a clean reset.
                        if args.no_spawn or attempt == 2:
                            rec = error_record(case, rep, f"server connection lost ({type(exc).__name__}), attempt {attempt}")
                            break
                        print(f"{label} {case['id']}: server connection lost ({type(exc).__name__}); "
                              "restarting services and retrying the check", flush=True)
                        stop(procs)
                        procs[:] = spawn(args.mode, not args.no_egress_canary)
                records.append(rec)
                partial_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
                channels = ",".join(rec["channels"])
                mark_str = "LEAK" if rec["leak_any"] else ("ERR" if rec["error"] else "ok")
                print(f"{label} {case['id']:13} rep{rep} {mark_str:4} {channels}", flush=True)
    finally:
        stop(procs)

    records.sort(key=lambda r: (order[r["id"]], r["repeat"]))
    summary = defaultdict(lambda: {"runs": 0, "leak_answer": 0, "leak_any": 0, "errors": 0})
    for rec in records:
        for key in (rec["route"], "ALL"):
            s = summary[key]
            s["runs"] += 1
            s["leak_answer"] += rec["leak_answer"]
            s["leak_any"] += rec["leak_any"]
            s["errors"] += bool(rec.get("error"))
    health = {"mode": args.mode, "llm": config.LLM_PROVIDER, "llm_model": config.LLM_MODEL if config.LLM_PROVIDER != "mock" else None,
              "egress_canary": not args.no_egress_canary, "repeats": repeats,
              "firewall": args.firewall if args.mode == "B2" else None}
    out = {"meta": health, "summary": summary, "records": records}
    final_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    partial_path.unlink(missing_ok=True)
    print(f"\n{label}: route      answers-only   all-channels")
    for route, s in summary.items():
        errs = f", {s['errors']} error(s)" if s["errors"] else ""
        print(f"{label}: {route:10} {s['leak_answer'] / s['runs']:>10.0%} {s['leak_any'] / s['runs']:>14.0%}   (n={s['runs']}{errs})")


if __name__ == "__main__":
    main()
