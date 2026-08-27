#!/usr/bin/env bash
# Point Proofmark at OWASP Juice Shop — a deliberately vulnerable app — to see
# what the agent actually proves. This is the real accuracy test: it needs your
# LLM key, and it runs against a target you fully control.
#
# Usage:
#   export ANTHROPIC_API_KEY=...        # or OPENAI_API_KEY / AZURE_API_KEY
#   ./run.sh                            # graph strategy, default model
#   ./run.sh single                     # one agent instead of the recon->exploit graph
#
#   # pick a STRONG model (this is the accuracy lever) and go deeper:
#   MODEL=anthropic/claude-opus-4-1 STEPS=100 ./run.sh graph
#   MODEL=openai/gpt-4o             STEPS=100 ./run.sh graph
#
# Juice Shop is an Angular single-page app, so a lot of its bugs are client-side.
# Build the browser sandbox once first for full coverage:  proofmark build-sandbox
set -euo pipefail

PORT="${PORT:-3001}"
STRATEGY="${1:-graph}"
MODEL="${MODEL:-anthropic/claude-sonnet-4-6}"   # override with a stronger model
STEPS="${STEPS:-60}"                            # raise for deeper hunts
NAME="juice-shop"
REPORT="juice-shop-report-$(echo "$MODEL" | tr '/:' '__').md"

echo "==> starting OWASP Juice Shop on :${PORT}"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "${PORT}:3000" bkimminich/juice-shop >/dev/null
echo "    waiting for it to come up..."
until curl -fsS -o /dev/null "http://localhost:${PORT}/"; do sleep 2; done
echo "    up: http://localhost:${PORT}"

# On Docker Desktop (macOS/Windows) the sandbox reaches the host at
# host.docker.internal. On Linux, run Juice Shop and Proofmark on the same Docker
# network instead, or add --add-host=host.docker.internal:host-gateway.
TARGET="http://host.docker.internal:${PORT}"

echo "==> proofmark doctor"
proofmark doctor || { echo "fix the above first"; exit 1; }

echo "==> scanning ${TARGET}  (strategy: ${STRATEGY}, model: ${MODEL}, steps: ${STEPS})"
proofmark scan \
  -t "${TARGET}" \
  --authorized \
  --operator "accuracy-test" \
  --model "${MODEL}" \
  --strategy "${STRATEGY}" \
  --max-steps "${STEPS}" \
  -o "${REPORT}"

echo
echo "==> done. Report: ${REPORT}"
echo "    Run record + signed manifest: proofmark_runs/<id>/"
echo "    Verify:  proofmark verify proofmark_runs/<id>"
echo "    Replay:  proofmark replay proofmark_runs/<id>"
echo "    Stop the target with: docker rm -f ${NAME}"
