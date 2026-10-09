# One-command setup on Windows:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
# Needs Docker Desktop (running), Python 3.12 through uv, and Ollama for the real model.
#   -SkipServices   don't start Postgres and Redis (they are already running)
#   -SkipModel      don't pull qwen3:4b (the mock model needs nothing)
param([switch]$SkipServices, [switch]$SkipModel)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Need($cmd, $hint) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found. $hint" } }

Need uv "Install it from https://docs.astral.sh/uv/"
if (-not $SkipServices) {
    Need docker "Install Docker Desktop and start it."
    Step "Starting Postgres and Redis"
    docker compose up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose failed. If Windows reserves port 55432 (netsh interface ipv4 show excludedportrange protocol=tcp), set `$env:TG_PG_PORT to a free port such as 45432 and run this again." }
    $deadline = (Get-Date).AddMinutes(2)
    do { Start-Sleep 2; $health = docker compose ps --format "{{.Health}}" } until ((@($health) -notcontains "starting") -or (Get-Date) -gt $deadline)
}

Step "Python environment"
if (-not (Test-Path .venv)) { uv venv --python 3.12 .venv }
uv pip install --python .venv\Scripts\python.exe -e ".[embed,pii,dev]" -c constraints.txt
.venv\Scripts\python.exe -m spacy download en_core_web_sm

Step "Seeding 3 companies (150 documents, 60 tickets, 222 canaries)"
.venv\Scripts\python.exe -m app.seed
if ($LASTEXITCODE -ne 0) { throw "seeding failed: is Postgres up?" }

if (-not $SkipModel) {
    if (Get-Command ollama -ErrorAction SilentlyContinue) { Step "Pulling qwen3:4b"; ollama pull qwen3:4b }
    else { Write-Host "Ollama not found: the real model is unavailable, but LLM_PROVIDER=mock works." -ForegroundColor Yellow }
}

Step "Unit tests"
.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "`nReady. Try:" -ForegroundColor Green
Write-Host "  .venv\Scripts\python.exe -m attacks.demo      # B0 vs B3 in about 30 seconds"
Write-Host "  .venv\Scripts\python.exe -m attacks.bench     # the whole benchmark (hours on Qwen)"
