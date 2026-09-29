"""Run the whole benchmark for the current LLM, end to end, resumably.

    python -m attacks.bench [--eval-per-tenant 5]

Steps: attack runs B0-B3, B3 without the egress canary check, utility eval B0-B3, results table.
Each step is skipped when its result file exists, and interrupted runs continue from their
partial file, so the command can simply be re-run after a crash or reboot. Progress goes to
results/<model>/progress.log (the process writes it itself, so it can run detached).
"""

import argparse
import subprocess
import sys
import time
from datetime import datetime

from attacks.run import RESULTS, ROOT


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-per-tenant", type=int, default=5)
    args = ap.parse_args()

    modes = ["B0", "B1", "B2", "B3"]
    steps = [["attacks.run", "--mode", m, "--resume"] for m in modes]
    steps.append(["attacks.run", "--mode", "B3", "--no-egress-canary", "--resume"])
    steps += [["eval.run_eval", "--mode", m, "--per-tenant", str(args.eval_per_tenant), "--resume"] for m in modes]
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
