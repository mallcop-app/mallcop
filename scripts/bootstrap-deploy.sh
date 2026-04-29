#!/usr/bin/env bash
# bootstrap-deploy.sh — Provision a mallcop deployment dir's .mallcop/ tree.
#
# This script is the quick-and-dirty stand-in for `mallcop init` until the
# OSS CLI ships its own bootstrap. The output layout is identical to what
# `mallcop init` will eventually produce, so a deployment provisioned here
# continues working without modification once the real CLI lands.
#
# See docs/design/deployment-and-identity.md (mallcop-pro) for the full design.
#
# Usage:
#   MALLCOP_HOME=~/projects/mallcop-deploy \
#   FORGE_API_KEY=forge-sk-... \
#   MODEL=claude-haiku-4-5 \
#   RUN_ID=$(basename "$MALLCOP_HOME")-$(date +%Y%m%d) \
#   scripts/bootstrap-deploy.sh
#
# Required:
#   MALLCOP_HOME    Absolute path to the deployment dir (must exist).
#   FORGE_API_KEY   Inference key (BYOK Anthropic key or mallcop-sk-* for pro).
#
# Optional:
#   MODEL           Default: claude-haiku-4-5
#   RUN_ID          Default: <basename>-<YYYYMMDD>
#   FORGE_API_URL   Default: https://forge.3dl.dev
#   PROTOCOL        Default: invite-only (use 'open' for hermetic dev runs)
#   FORCE           If 'yes', overwrite existing identity files (default: no)
#
# Idempotent: re-running with the same MALLCOP_HOME preserves existing
# identities. To start fresh, delete .mallcop/ first or set FORCE=yes.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DISPOSITIONS=(
  triage
  investigate
  deep-investigate
  investigate-merge
  escalate
  heal
  judge
  report
  mallcop
)

err() { echo "Error: $*" >&2; exit 1; }
note() { echo "[bootstrap-deploy] $*"; }

[[ -n "${MALLCOP_HOME:-}" ]] || err "MALLCOP_HOME is required"
[[ -d "${MALLCOP_HOME}" ]]   || err "MALLCOP_HOME (${MALLCOP_HOME}) does not exist"
[[ -n "${FORGE_API_KEY:-}" ]] || err "FORGE_API_KEY is required"

MALLCOP_HOME="$(cd "${MALLCOP_HOME}" && pwd)"   # resolve to absolute
MODEL="${MODEL:-claude-haiku-4-5}"
RUN_ID="${RUN_ID:-$(basename "${MALLCOP_HOME}")-$(date +%Y%m%d)}"
FORGE_API_URL="${FORGE_API_URL:-https://forge.3dl.dev}"
PROTOCOL="${PROTOCOL:-invite-only}"
FORCE="${FORCE:-no}"

CF_HOME="${MALLCOP_HOME}/.mallcop"
export CF_HOME

note "MALLCOP_HOME = ${MALLCOP_HOME}"
note "RUN_ID       = ${RUN_ID}"
note "PROTOCOL     = ${PROTOCOL}"

mkdir -p "${CF_HOME}"

# generate_identity_into <path> — writes a fresh Ed25519 identity.json at <path>.
# Uses 'cf init --session' to generate a temp identity, then moves the keypair
# into place. Each deployment thus gets its own identities (no global
# ~/.campfire/agents/ collision across deployments).
generate_identity_into() {
  local target="$1"
  local label="$2"
  if [[ -f "${target}" && "${FORCE}" != "yes" ]]; then
    note "${label}: identity.json already present (skipped)"
    return 0
  fi
  note "${label}: generating fresh identity"
  mkdir -p "$(dirname "${target}")"
  local session_dir
  session_dir=$(cf init --session 2>/dev/null | head -1)
  if [[ -z "${session_dir}" || ! -f "${session_dir}/identity.json" ]]; then
    err "${label}: cf init --session did not produce identity.json"
  fi
  cp "${session_dir}/identity.json" "${target}"
  rm -rf "${session_dir}"
}

# 1. Operator identity
generate_identity_into "${CF_HOME}/identity.json" "operator"

# 2. Automaton identity
generate_identity_into "${CF_HOME}/automaton/identity.json" "automaton"
AUTOMATON_PUBKEY=$(python3 -c "
import base64, json
with open('${CF_HOME}/automaton/identity.json') as f:
    d = json.load(f)
print(base64.b64decode(d['public_key']).hex())
")

# 3. Disposition identities
for d in "${DISPOSITIONS[@]}"; do
  generate_identity_into "${CF_HOME}/agents/${d}/identity.json" "disposition ${d}"
done

# 4. Disposition POST.md symlinks (so mallcop-legion can be the spec source)
note "linking POST.md specs from ${REPO_ROOT}/agents/<d>/POST.md"
for d in "${DISPOSITIONS[@]}"; do
  src="${REPO_ROOT}/agents/${d}/POST.md"
  dst="${CF_HOME}/agents/${d}/POST.md"
  if [[ -f "${src}" ]]; then
    ln -sfn "${src}" "${dst}"
  else
    note "  warning: ${src} missing — disposition ${d} will lack a POST.md"
  fi
done

# 5. Work campfire
WORK_CF_FILE="${CF_HOME}/work-campfire.id"
if [[ -s "${WORK_CF_FILE}" && "${FORCE}" != "yes" ]]; then
  WORK_CF=$(cat "${WORK_CF_FILE}")
  note "work campfire: existing ${WORK_CF:0:12}... (from ${WORK_CF_FILE})"
else
  note "work campfire: cf create --protocol ${PROTOCOL}"
  WORK_CF_DESC="$(basename "${MALLCOP_HOME}")-work"
  WORK_CF=$(cf create --description "${WORK_CF_DESC}" --no-config --protocol "${PROTOCOL}" --json | python3 -c "import json,sys; print(json.load(sys.stdin)['campfire_id'])")
  echo "${WORK_CF}" > "${WORK_CF_FILE}"
  note "work campfire: ${WORK_CF:0:12}... → ${WORK_CF_FILE}"
fi

# 6. Admit automaton to work campfire (idempotent — admit twice is fine)
if [[ "${PROTOCOL}" == "invite-only" ]]; then
  note "admitting automaton ${AUTOMATON_PUBKEY:0:12}... to work campfire"
  cf admit "${WORK_CF}" "${AUTOMATON_PUBKEY}" >/dev/null 2>&1 || \
    note "  (admit returned non-zero; may already be a member)"
fi

# 7. Render chart
CHART_OUT="${CF_HOME}/chart.toml"
note "rendering chart → ${CHART_OUT}"
RUN_ID="${RUN_ID}" \
FORGE_API_KEY="${FORGE_API_KEY}" \
FORGE_API_URL="${FORGE_API_URL}" \
MODEL="${MODEL}" \
WORK_CAMPFIRE="${WORK_CF}" \
MALLCOP_HOME="${MALLCOP_HOME}" \
"${SCRIPT_DIR}/render-chart.sh" \
  "${REPO_ROOT}/charts/mallcop-operational.toml.tmpl" \
  "${CHART_OUT}" >/dev/null

note "done"
echo
echo "Deployment provisioned at ${MALLCOP_HOME}"
echo "  CF_HOME            = ${CF_HOME}"
echo "  work campfire      = ${WORK_CF}"
echo "  automaton pubkey   = ${AUTOMATON_PUBKEY}"
echo "  chart              = ${CHART_OUT}"
echo
echo "Next:"
echo "  CF_HOME=${CF_HOME} we start --chart ${CHART_OUT}"
echo "  mallcop-academy --deployment ${MALLCOP_HOME} --scenario AC-01-external-access-stolen-cred"
