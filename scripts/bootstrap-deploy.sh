#!/usr/bin/env bash
# bootstrap-deploy.sh — Provision a fully-isolated mallcop deployment under
# $MALLCOP_HOME/.mallcop/. No state leaks to ~/.legion/ or ~/.campfire/.
#
# Stand-in for `mallcop init` until the OSS CLI ships. Output layout matches
# what `mallcop init` will eventually produce — deployments provisioned here
# keep working without modification once the real CLI lands.
#
# See docs/design/deployment-and-identity.md (mallcop-pro) for the design.
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
#   FORGE_API_KEY   Inference key (BYOK or mallcop-sk-* for pro).
#
# Optional:
#   MODEL           Default: claude-haiku-4-5
#   RUN_ID          Default: <basename>-<YYYYMMDD>
#   FORGE_API_URL   Default: https://forge.3dl.dev
#   PROTOCOL        Default: invite-only (use 'open' for hermetic dev runs)
#   FORCE           If 'yes', overwrite existing identity files
#
# Idempotent. Re-running preserves existing identities and the work campfire.
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

MALLCOP_HOME="$(cd "${MALLCOP_HOME}" && pwd)"
MODEL="${MODEL:-claude-haiku-4-5}"
RUN_ID="${RUN_ID:-$(basename "${MALLCOP_HOME}")-$(date +%Y%m%d)}"
FORGE_API_URL="${FORGE_API_URL:-https://forge.3dl.dev}"
PROTOCOL="${PROTOCOL:-invite-only}"
FORCE="${FORCE:-no}"

DEPLOY_DIR="${MALLCOP_HOME}/.mallcop"

# Per-folder isolation: every legion / cf command runs against this deployment's
# own state, never ~/.legion/ or ~/.campfire/.
export CF_HOME="${DEPLOY_DIR}"
export LEGION_FLEET_REGISTRY="${DEPLOY_DIR}/fleet.json"
export LEGION_JAIL_ROOT="${DEPLOY_DIR}/jails"

note "MALLCOP_HOME = ${MALLCOP_HOME}"
note "DEPLOY_DIR   = ${DEPLOY_DIR}"
note "RUN_ID       = ${RUN_ID}"
note "PROTOCOL     = ${PROTOCOL}"
note "isolation    = CF_HOME=${CF_HOME}"
note "             | LEGION_FLEET_REGISTRY=${LEGION_FLEET_REGISTRY}"
note "             | LEGION_JAIL_ROOT=${LEGION_JAIL_ROOT}"

mkdir -p "${DEPLOY_DIR}/jails" "${DEPLOY_DIR}/campfires" "${DEPLOY_DIR}/agents" "${DEPLOY_DIR}/secrets" "${DEPLOY_DIR}/automata"

# generate_identity_into <path> <label> — writes a fresh Ed25519 identity.json
# at <path>. Uses cf init --session in a temp dir, then copies the keypair.
# Each deployment gets its own keys; no global ~/.campfire/agents/ collision.
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
  # cf init --session uses its own ephemeral CF_HOME; safe to call regardless
  # of the export CF_HOME above.
  session_dir=$(env -u CF_HOME cf init --session 2>/dev/null | head -1)
  [[ -n "${session_dir}" && -f "${session_dir}/identity.json" ]] \
    || err "${label}: cf init --session did not produce identity.json"
  cp "${session_dir}/identity.json" "${target}"
  rm -rf "${session_dir}"
}

# 1. Operator+automaton identity (single key for v1; admission boundary
# is a v2 concern). The chart's [identity].key_file points here.
generate_identity_into "${DEPLOY_DIR}/identity.json" "operator+automaton"
AUTOMATON_PUBKEY=$(python3 -c "
import base64, json
with open('${DEPLOY_DIR}/identity.json') as f:
    d = json.load(f)
print(base64.b64decode(d['public_key']).hex())
")
note "operator+automaton pubkey: ${AUTOMATON_PUBKEY:0:16}..."

# 2. Disposition identity SHELLS — exist only so the legion pilot's
# LoadDispositionRoster accepts the disposition. Per legion code comment:
# "Dispositions are AGENT.md specs ... they inherit their spawner's identity
# and do NOT register in the Identity table." These keys are not used
# cryptographically at runtime. We still generate real keypairs (matches the
# loader's expectations and protects against a future legion rev that does
# use them).
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

# 4. Work campfire — created via `rd init` because legion's ReadyWorkSource
# expects a campfire set up with the rd work-management convention (reception
# requirements, convention:operation declarations). A bare `cf create` produces
# a campfire whose SDK subscribe path legion's tools-feed rejects with
# "not a member" — the rd init flow installs the right metadata.
#
# rd init writes .campfire/root to the cwd, so we run it from MALLCOP_HOME
# (the deployment's project root). The campfire ID is read back from
# .campfire/root.
WORK_CF_FILE="${DEPLOY_DIR}/work-campfire.id"
RD_ROOT_FILE="${MALLCOP_HOME}/.campfire/root"
if [[ -s "${WORK_CF_FILE}" && -f "${RD_ROOT_FILE}" && "${FORCE}" != "yes" ]]; then
  WORK_CF=$(cat "${WORK_CF_FILE}")
  note "work campfire: existing ${WORK_CF:0:12}... (from ${WORK_CF_FILE})"
else
  note "work campfire: rd init --name $(basename "${MALLCOP_HOME}")"
  ( cd "${MALLCOP_HOME}" && rd init --name "$(basename "${MALLCOP_HOME}")" >/dev/null 2>&1 ) \
    || err "rd init failed in ${MALLCOP_HOME}"
  [[ -f "${RD_ROOT_FILE}" ]] || err "rd init did not create ${RD_ROOT_FILE}"
  WORK_CF=$(cat "${RD_ROOT_FILE}")
  echo "${WORK_CF}" > "${WORK_CF_FILE}"
  note "work campfire: ${WORK_CF:0:12}... → ${WORK_CF_FILE}"
fi

# 5. Render chart. All paths point inside DEPLOY_DIR — no ~/.legion or
# ~/.campfire references in the rendered output.
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

# 6. Write an activate script so users can opt into the deployment-scoped
# envelope without remembering the env vars manually:
#   source $MALLCOP_HOME/.mallcop/activate
#   we tail mallcop-operational-...
cat > "${DEPLOY_DIR}/activate" <<EOF
# Source this file to scope cf and we to this deployment.
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
echo "  identity pubkey   = ${AUTOMATON_PUBKEY}"
echo "  work campfire     = ${WORK_CF}"
echo "  chart             = ${CHART_OUT}"
echo "  activate envelope = source ${DEPLOY_DIR}/activate"
echo
echo "Next:"
echo "  source ${DEPLOY_DIR}/activate"
echo "  we start --chart ${CHART_OUT}"
echo "  mallcop-academy --deployment ${MALLCOP_HOME} --scenario AC-01-external-access-stolen-cred"
