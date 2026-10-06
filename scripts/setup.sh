#!/usr/bin/env bash
# One-command setup on macOS / Linux:  bash scripts/setup.sh
# Needs Docker (running), uv, and Ollama for the real model.
#   --skip-services   don't start Postgres and Redis (they are already running)
#   --skip-model      don't pull qwen3:4b (the mock model needs nothing)
set -euo pipefail
cd "$(dirname "$0")/.."

skip_services=0; skip_model=0
for arg in "$@"; do
  case "$arg" in
    --skip-services) skip_services=1 ;;
    --skip-model) skip_model=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
step() { printf '\n== %s\n' "$1"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "$1 not found. $2" >&2; exit 1; }; }

need uv "Install it from https://docs.astral.sh/uv/"
if [ "$skip_services" -eq 0 ]; then
  need docker "Install Docker and start it."
  step "Starting Postgres and Redis"
  docker compose up -d
  for _ in $(seq 60); do
    docker compose ps --format '{{.Health}}' | grep -q starting || break
    sleep 2
  done
fi

step "Python environment"
[ -d .venv ] || uv venv --python 3.12 .venv
PY=.venv/bin/python; [ -x "$PY" ] || PY=.venv/Scripts/python.exe
uv pip install --python "$PY" -e ".[embed,pii,dev]" -c constraints.txt
"$PY" -m spacy download en_core_web_sm

step "Seeding 3 companies (150 documents, 60 tickets, 222 canaries)"
"$PY" -m app.seed

if [ "$skip_model" -eq 0 ]; then
  if command -v ollama >/dev/null 2>&1; then step "Pulling qwen3:4b"; ollama pull qwen3:4b
  else echo "Ollama not found: the real model is unavailable, but LLM_PROVIDER=mock works."; fi
fi

step "Unit tests"
"$PY" -m pytest -q

printf '\nReady. Try:\n  %s -m attacks.demo      # B0 vs B3 in about 30 seconds\n  %s -m attacks.bench     # the whole benchmark (hours on Qwen)\n' "$PY" "$PY"
