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

# 4. Render chart. Worksource campfire, admission, and join records are
# entirely legion's job (constellation init + RestoreMemberships at boot).
# We do NOT pre-create or admit campfires here.
CHART_OUT="${DEPLOY_DIR}/chart.toml"
note "rendering chart → ${CHART_OUT}"
RUN_ID="${RUN_ID}" \
FORGE_API_KEY="${FORGE_API_KEY}" \
FORGE_API_URL="${FORGE_API_URL}" \
MODEL="${MODEL}" \
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
