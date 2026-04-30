#!/usr/bin/env bash
# bootstrap-deploy.sh — Provision a mallcop deployment under
# $MALLCOP_HOME/.mallcop/. Generates only what legion does NOT generate
# (identity files, disposition shells, rendered chart, env envelope).
# Stays out of legion's campfires entirely — campfire creation, admission,
# joining, and constellation init are all legion's responsibility.
#
# Stand-in for `mallcop init` until the OSS CLI ships.
# Spec: docs/design/deployment-and-identity.md (mallcop-pro).
#
# Usage:
#   MALLCOP_HOME=~/projects/mallcop-deploy \
#   FORGE_API_KEY=forge-sk-... \
#   scripts/bootstrap-deploy.sh
#
# Required:
#   MALLCOP_HOME    Absolute path to the deployment dir (must exist).
#   FORGE_API_KEY   Inference key (BYOK or mallcop-sk-* for pro).
#
# Optional:
#   MODEL           Default: claude-haiku-4-5
#   RUN_ID          Default: <basename>-<YYYYMMDD>
#   FORGE_API_URL   Default: https://forge.3dl.dev
#   FORCE           If 'yes', overwrite existing identity files
#
# Idempotent. Re-running preserves identities. Does NOT touch campfires.
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

err()  { echo "Error: $*" >&2; exit 1; }
note() { echo "[bootstrap-deploy] $*"; }

[[ -n "${MALLCOP_HOME:-}" ]] || err "MALLCOP_HOME is required"
[[ -d "${MALLCOP_HOME}" ]]   || err "MALLCOP_HOME (${MALLCOP_HOME}) does not exist"
[[ -n "${FORGE_API_KEY:-}" ]] || err "FORGE_API_KEY is required"

MALLCOP_HOME="$(cd "${MALLCOP_HOME}" && pwd)"
MODEL="${MODEL:-claude-haiku-4-5}"
RUN_ID="${RUN_ID:-$(basename "${MALLCOP_HOME}")-$(date +%Y%m%d)}"
FORGE_API_URL="${FORGE_API_URL:-https://forge.3dl.dev}"
FORCE="${FORCE:-no}"

DEPLOY_DIR="${MALLCOP_HOME}/.mallcop"

note "MALLCOP_HOME = ${MALLCOP_HOME}"
note "DEPLOY_DIR   = ${DEPLOY_DIR}"
note "RUN_ID       = ${RUN_ID}"

mkdir -p \
  "${DEPLOY_DIR}/jails" \
  "${DEPLOY_DIR}/campfires" \
  "${DEPLOY_DIR}/agents" \
  "${DEPLOY_DIR}/secrets" \
  "${DEPLOY_DIR}/automata"

# generate_identity_into <path> <label> — writes a fresh Ed25519 identity.json.
# Uses cf init --session in a temp dir (its own ephemeral CF_HOME), then
# copies the keypair. Each deployment gets its own keys; no cross-deployment
# state.
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
  session_dir=$(env -u CF_HOME cf init --session 2>/dev/null | head -1)
  [[ -n "${session_dir}" && -f "${session_dir}/identity.json" ]] \
    || err "${label}: cf init --session did not produce identity.json"
  cp "${session_dir}/identity.json" "${target}"
  rm -rf "${session_dir}"
}

# 1. Operator+automaton identity. The chart's [identity].key_file points here.
generate_identity_into "${DEPLOY_DIR}/identity.json" "operator+automaton"

# 1a. Mirror the operator/automaton identity to campfire-identity.json so
# legion's CampfireClient (boot.go:140 — uses <identityDir>/campfire-identity.json,
# NOT the chart's key_file) shares the same keypair as the one rd init admits
# to the work campfire. Without this, NewCampfireClient generates a fresh
# keypair on first boot and the SDK reads the work campfire as a non-member,
# returning empty. (legion-side fix would be to use the chart's key_file
# directly; this mirror keeps deployments working without that change.)
cp "${DEPLOY_DIR}/identity.json" "${DEPLOY_DIR}/campfire-identity.json"

# 2. Disposition identity SHELLS. Per legion's DispositionRoster code comment,
# dispositions inherit their spawner's identity at runtime — these files exist
# only so LoadDispositionRoster registers each disposition. Generated as real
# keypairs in case a future legion rev makes them load-bearing.
for d in "${DISPOSITIONS[@]}"; do
  generate_identity_into "${DEPLOY_DIR}/agents/${d}/identity.json" "disposition ${d}"
done

# 3. Disposition POST.md symlinks → mallcop-legion bundle source
for d in "${DISPOSITIONS[@]}"; do
  src="${REPO_ROOT}/agents/${d}/POST.md"
  dst="${DEPLOY_DIR}/agents/${d}/POST.md"
  if [[ -f "${src}" ]]; then
    ln -sfn "${src}" "${dst}"
  else
    note "  warning: ${src} missing — disposition ${d} has no POST.md"
  fi
done
note "disposition POST.md specs linked from ${REPO_ROOT}/agents/"

# 4. Work campfire — created via rd init (canonical mallcop work source).
# rd init writes .campfire/root in MALLCOP_HOME and admits the operator/
# automaton identity. Legion v0.7.3+ handles store-side membership
# restoration at boot (RestoreMemberships) and Subscribe auto-join shield —
# no operator-side cf join ceremony required.
RD_ROOT_FILE="${MALLCOP_HOME}/.campfire/root"
WORK_CF_FILE="${DEPLOY_DIR}/work-campfire.id"
if [[ -s "${WORK_CF_FILE}" && -f "${RD_ROOT_FILE}" && "${FORCE}" != "yes" ]]; then
  WORK_CF=$(cat "${WORK_CF_FILE}")
  note "work campfire: existing ${WORK_CF:0:12}... (from ${WORK_CF_FILE})"
else
  note "work campfire: rd init --name $(basename "${MALLCOP_HOME}")"
  ( cd "${MALLCOP_HOME}" && CF_HOME="${DEPLOY_DIR}" rd init --name "$(basename "${MALLCOP_HOME}")" >/dev/null 2>&1 ) \
    || err "rd init failed in ${MALLCOP_HOME}"
  [[ -f "${RD_ROOT_FILE}" ]] || err "rd init did not create ${RD_ROOT_FILE}"
  WORK_CF=$(cat "${RD_ROOT_FILE}")
  echo "${WORK_CF}" > "${WORK_CF_FILE}"
  note "work campfire: ${WORK_CF:0:12}... → ${WORK_CF_FILE}"
fi

# 5. Render chart with the resolved work campfire.
CHART_OUT="${DEPLOY_DIR}/chart.toml"
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

# 5. Activate envelope — every cf/we/rd/mallcop-academy invocation against
# this deployment uses these env vars to keep all state inside DEPLOY_DIR.
cat > "${DEPLOY_DIR}/activate" <<EOF
# Source this file to scope cf/we/rd to this deployment.
#   source ${DEPLOY_DIR}/activate
export MALLCOP_HOME="${MALLCOP_HOME}"
export CF_HOME="${DEPLOY_DIR}"
export LEGION_FLEET_REGISTRY="${DEPLOY_DIR}/fleet.json"
export LEGION_JAIL_ROOT="${DEPLOY_DIR}/jails"
EOF

note "done"
echo
echo "Deployment provisioned at ${MALLCOP_HOME}"
echo "  DEPLOY_DIR        = ${DEPLOY_DIR}"
echo "  identity          = ${DEPLOY_DIR}/identity.json"
echo "  chart             = ${CHART_OUT}"
echo "  activate envelope = source ${DEPLOY_DIR}/activate"
echo
echo "Next:"
echo "  source ${DEPLOY_DIR}/activate"
echo "  we start --chart ${CHART_OUT}        # legion handles all campfire setup"
echo "  mallcop-academy --deployment ${MALLCOP_HOME} --scenario AC-01-external-access-stolen-cred"
