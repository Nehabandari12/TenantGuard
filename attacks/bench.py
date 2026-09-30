"""Run the whole benchmark for the current LLM, end to end, resumably.

    python -m attacks.bench [--eval-per-tenant 5] [--eval-agent-per-tenant 1]
    python -m attacks.bench --repeats 3 --repeat-modes B0,B1,B2    # add repeats 2-3 to those runs

Steps: attack runs B0-B3, B3 without the egress canary check, utility eval B0-B3, the LLM judge on the
eval answers (local Ollama models only), results table.
Each attack step runs only the checks its saved results don't have yet: an interrupted run continues
from its partial file, and a finished one gets just the checks added to the case file since. Eval steps
are skipped once finished (rows saved before answers were kept are asked again, for the judge). So the command can simply be re-run after a crash, a reboot or new checks. Progress goes to
results/<model>/progress.log (the process writes it itself, so it can run detached).
"""

import argparse
import subprocess
import sys
import time
from datetime import datetime

from app import config
from attacks.run import RESULTS, ROOT


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-per-tenant", type=int, default=5)
    ap.add_argument("--eval-agent-per-tenant", type=int, default=1, help="agent tasks of each kind per tenant")
    ap.add_argument("--repeats", type=int, default=None, help="repeats per check (added to what is saved)")
    ap.add_argument("--repeat-modes", default="B0,B1,B2,B3,B3_nocanary",
                    help="attack runs that get --repeats; the others keep what they have")
    args = ap.parse_args()

    modes = ["B0", "B1", "B2", "B3"]
    repeat_modes = set(args.repeat_modes.split(","))

    def attack(label: str) -> list[str]:
        step = ["attacks.run", "--mode", label.split("_")[0], "--resume"]
        if label.endswith("_nocanary"):
            step.append("--no-egress-canary")
        if args.repeats and label in repeat_modes:
            step += ["--repeats", str(args.repeats)]
        return step

    steps = [attack(m) for m in modes] + [attack("B3_nocanary")]
    steps += [["eval.run_eval", "--mode", m, "--per-tenant", str(args.eval_per_tenant),
               "--agent-per-tenant", str(args.eval_agent_per_tenant), "--resume"] for m in modes]
    if config.LLM_PROVIDER == "ollama":
        steps.append(["eval.judge"])  # grades the saved answers with the same local model; skips graded ones
    steps.append(["attacks.table"])

    RESULTS.mkdir(parents=True, exist_ok=True)
    with open(RESULTS / "progress.log", "a", encoding="utf-8") as log:
        def note(msg: str) -> None:
            log.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
            log.flush()

        note(f"bench start: {len(steps)} steps")
        for step in steps:
            t0 = time.time()
            note("start " + " ".join(step))
            rc = subprocess.run([sys.executable, "-u", "-m", *step], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode
            note(f"end {' '.join(step)} rc={rc} after {(time.time() - t0) / 60:.1f} min")
            if rc != 0:
                note("BENCH FAILED")
                sys.exit(rc)
        note("ALL_DONE")


if __name__ == "__main__":
    main()
