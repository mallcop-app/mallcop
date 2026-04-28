#!/usr/bin/env bash
# Multi-scenario smoke for legion v0.4.2 API spawn path + legion.tools.
# Uses the canonical rd init → invite → join pattern so operator and automaton
# share the same campfire via a beacon-resolved transport dir.
#
# Env overrides:
#   RUN_ID=... (default smoke-<timestamp>)
#   MODEL=... (default glm-4.7)
#   SCENARIOS_DIR=... (default exams/scenarios/auth → the 5 AF-* scenarios)
#   WAIT_SECS=... (default 300)
set -euo pipefail

REPO="/home/baron/projects/mallcop-legion"
RUN_ID="${RUN_ID:-smoke-$(date +%Y%m%d-%H%M%S)}"
MODEL="${MODEL:-glm-4.7}"
SCENARIOS_DIR="${SCENARIOS_DIR:-${REPO}/exams/scenarios/auth}"
WAIT_SECS="${WAIT_SECS:-300}"
FORGE_API_URL="https://forge.3dl.dev"
FORGE_API_KEY="REDACTED-MALLCOP-SK-PR21"

RUN_DIR="${REPO}/.run/exam-${RUN_ID}"
OP_CF_HOME="${RUN_DIR}/op-cf"
WORKER_CF_HOME="${RUN_DIR}/worker-cf"
PROJECT_DIR="${RUN_DIR}/project"
WE_BIN="${REPO}/bin/we"
RD_BIN="$(command -v rd)"
EXAM_SEED="${REPO}/bin/exam-seed"
TOOL_BIN_DIR="${REPO}/bin"
CHART="${RUN_DIR}/chart.toml"
LOG="${RUN_DIR}/we.log"

cleanup() {
  if [[ -f "${RUN_DIR}/we.pid" ]]; then
    kill "$(cat "${RUN_DIR}/we.pid")" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo ">>> run_id=${RUN_ID}  model=${MODEL}  scenarios_dir=${SCENARIOS_DIR}"
NUM_SCENARIOS=$(find "${SCENARIOS_DIR}" -type f -name '*.yaml' ! -name '_*' 2>/dev/null | wc -l)
echo "    scenarios to seed: ${NUM_SCENARIOS}"

echo ">>> fresh run dir: ${RUN_DIR}"
rm -rf "${RUN_DIR}"
mkdir -p "${OP_CF_HOME}" "${WORKER_CF_HOME}" "${PROJECT_DIR}"

echo ">>> [operator] rd init project campfire"
cd "${PROJECT_DIR}"
CF_HOME="${OP_CF_HOME}" "${RD_BIN}" init --name "exam-${RUN_ID}" 2>&1 | tail -10

if [[ ! -f "${PROJECT_DIR}/.campfire/root" ]]; then
  echo "ERROR: rd init did not create .campfire/root" >&2
  exit 1
fi
CAMPFIRE_ID="$(tr -d '[:space:]' < "${PROJECT_DIR}/.campfire/root")"
echo "    work campfire: ${CAMPFIRE_ID}"

echo ">>> [operator] rd invite agent token"
TOKEN="$(cd "${PROJECT_DIR}" && CF_HOME="${OP_CF_HOME}" "${RD_BIN}" invite --role agent --ttl 60m 2>&1 | grep -oE 'rdx1_[A-Za-z0-9_-]+' | head -1)"
[[ -z "${TOKEN}" ]] && { echo "ERROR: invite token" >&2; exit 1; }
echo "    token len=${#TOKEN}"

echo ">>> [worker] rd join <token>"
WORKER_PROJECT="${RUN_DIR}/worker-project"
mkdir -p "${WORKER_PROJECT}"
cd "${WORKER_PROJECT}"
CF_HOME="${WORKER_CF_HOME}" "${RD_BIN}" join "${TOKEN}" 2>&1 | tail -5

echo ">>> wire automaton identity"
"${WE_BIN}" init --name "${RUN_ID}-worker" >/dev/null
JOINED_IDENTITY="${WORKER_CF_HOME}/identity.json"
cp "${JOINED_IDENTITY}" "${RUN_DIR}/identity.json"
cp "${JOINED_IDENTITY}" "${RUN_DIR}/campfire-identity.json"

echo ">>> render chart"
sed \
  -e "s|{{MODEL}}|${MODEL}|g" \
  -e "s|{{RUN_ID}}|${RUN_ID}|g" \
  -e "s|{{FORGE_API_URL}}|${FORGE_API_URL}|g" \
  -e "s|{{FORGE_API_KEY}}|${FORGE_API_KEY}|g" \
  -e "s|{{TOOL_BIN_DIR}}|${TOOL_BIN_DIR}|g" \
  "${REPO}/charts/exam-bakeoff.toml.tmpl" > "${CHART}.tpl"
sed \
  -e "s|campfire = \"exam-${RUN_ID}\"|campfire = \"${CAMPFIRE_ID}\"|g" \
  -e "s|transport_dir = \".run/exam-${RUN_ID}/campfires\"|transport_dir = \"${OP_CF_HOME}/campfires\"|g" \
  "${CHART}.tpl" > "${CHART}"

echo ">>> [operator] seed ${NUM_SCENARIOS} scenarios from ${SCENARIOS_DIR}"
cd "${REPO}"
CF_HOME="${OP_CF_HOME}" "${EXAM_SEED}" \
  --campfire "${CAMPFIRE_ID}" \
  --run "${RUN_ID}" \
  --scenarios-dir "${SCENARIOS_DIR}" 2>&1 | tail -3

echo ">>> waiting 5s for messages to settle"
sleep 5

echo ">>> booting we (v0.4.2)"
cd "${REPO}"
CF_HOME="${WORKER_CF_HOME}" "${WE_BIN}" start --chart "${CHART}" -v > "${LOG}" 2>&1 &
echo "$!" > "${RUN_DIR}/we.pid"
echo "    we PID=$(cat "${RUN_DIR}/we.pid")"

EXPECTED_VERDICTS=${NUM_SCENARIOS}
echo ">>> waiting up to ${WAIT_SECS}s for ${EXPECTED_VERDICTS} judge:verdict messages"
for i in $(seq 1 $((WAIT_SECS / 5))); do
  sleep 5
  COUNT=$(CF_HOME="${OP_CF_HOME}" cf read "${CAMPFIRE_ID}" --all --tag judge:verdict --json 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
  if [[ "$COUNT" -ge "$EXPECTED_VERDICTS" ]]; then
    echo "    ${COUNT}/${EXPECTED_VERDICTS} verdicts at t=$((i*5))s"
    # wait a bit more for the report item
    sleep 15
    break
  fi
  if (( i % 6 == 0 )); then
    echo "    ...${COUNT}/${EXPECTED_VERDICTS} verdicts at t=$((i*5))s"
  fi
done

echo ">>> stopping we"
kill "$(cat "${RUN_DIR}/we.pid")" 2>/dev/null || true
sleep 2

echo ""
echo "=========================================="
echo "SMOKE RESULT — ${RUN_ID} / ${MODEL} / ${NUM_SCENARIOS} scenarios"
echo "=========================================="
echo ""

REPORTER="${REPO}/bin/smoke-report.py"

echo "--- triage resolutions (exam:scenario work:output) ---"
CF_HOME="${OP_CF_HOME}" cf read "${CAMPFIRE_ID}" --all --tag exam:scenario --tag work:output --json 2>/dev/null | "${REPORTER}" triage

echo ""
echo "--- judge verdicts (judge:verdict) ---"
CF_HOME="${OP_CF_HOME}" cf read "${CAMPFIRE_ID}" --all --tag judge:verdict --json 2>/dev/null | "${REPORTER}" judge

echo ""
echo "--- report (exam:report work:output) ---"
CF_HOME="${OP_CF_HOME}" cf read "${CAMPFIRE_ID}" --all --tag exam:report --tag work:output --json 2>/dev/null | "${REPORTER}" report

echo ""
echo "--- errors in we.log ---"
grep -E "Infer failed|ERROR" "${LOG}" 2>/dev/null | head -10 || echo "(no errors)"
echo ""
echo "Full log: ${LOG}"
