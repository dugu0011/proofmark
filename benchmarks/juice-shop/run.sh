#!/usr/bin/env bash
# Point Proofmark at OWASP Juice Shop — a deliberately vulnerable app — to see
# what the agent actually proves. This is the real accuracy test: it needs your
# LLM key, and it runs against a target you fully control.
#
# Usage:
#   export ANTHROPIC_API_KEY=...        # or OPENAI_API_KEY / AZURE_API_KEY
#   ./run.sh                            # single agent
#   ./run.sh graph                      # recon -> exploit graph
set -euo pipefail

PORT="${PORT:-3001}"
STRATEGY="${1:-graph}"
NAME="juice-shop"

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

echo "==> scanning ${TARGET} (strategy: ${STRATEGY})"
proofmark scan \
  -t "${TARGET}" \
  --authorized \
  --operator "accuracy-test" \
  --strategy "${STRATEGY}" \
  --max-steps 60 \
  -o "juice-shop-report.md"

echo
echo "==> done. Report: juice-shop-report.md"
echo "    Run record + signed manifest: proofmark_runs/<id>/"
echo "    Stop the target with: docker rm -f ${NAME}"
