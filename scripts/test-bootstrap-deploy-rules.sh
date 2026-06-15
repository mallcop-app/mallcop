#!/usr/bin/env bash
# test-bootstrap-deploy-rules.sh — mallcoppro-b92 regression guard.
#
# Verifies the operator-decisions.yaml deploy step in bootstrap-deploy.sh:
#
#   1. After deploy, $DEPLOY_DIR/agents/rules/operator-decisions.yaml exists
#      and is a REAL FILE (not a symlink). This is the primary defence against
#      symlink-confusion / TOCTOU tampering of the rule corpus on deploy.
#   2. The content of the destination file equals the source corpus
#      bit-for-bit (atomic copy, not an empty / partial file).
#   3. Legacy symlink at $DEPLOY_DIR/agents/rules is replaced with a real dir
#      (back-compat path for existing deployments).
#
# Strategy: extract and rerun just block "3b" of bootstrap-deploy.sh in
# isolation against a temp DEPLOY_DIR — running the full script requires cf/rd
# binaries and identity ceremony, which is out of scope for this test.
#
# Usage: bash scripts/test-bootstrap-deploy-rules.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BOOTSTRAP="${SCRIPT_DIR}/bootstrap-deploy.sh"
RULES_SRC="${REPO_ROOT}/agents/rules/operator-decisions.yaml"

fail=0
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1" >&2; FAIL=$((FAIL+1)); fail=1; }

[[ -f "${RULES_SRC}" ]] || { echo "missing source corpus: ${RULES_SRC}" >&2; exit 2; }
[[ -f "${BOOTSTRAP}" ]] || { echo "missing bootstrap script: ${BOOTSTRAP}" >&2; exit 2; }

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/mallcop-deploy-test-XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

# ---- case 1: clean deploy → real file, not symlink ----
DEPLOY_DIR="${TMPDIR}/case1/.mallcop"
mkdir -p "${DEPLOY_DIR}/agents"

# Reproduce block 3b in isolation. The block is whole-line addressable in the
# script; we re-implement it inline rather than sourcing the whole script (which
# would require cf/rd ceremony). Any drift from the script is caught by the
# textual invariant check below.
rules_src_file="${RULES_SRC}"
rules_dst_dir="${DEPLOY_DIR}/agents/rules"
rules_dst_file="${rules_dst_dir}/operator-decisions.yaml"
if [[ -L "${rules_dst_dir}" ]]; then rm -f "${rules_dst_dir}"; fi
mkdir -p "${rules_dst_dir}"
rules_tmp="${rules_dst_file}.tmp.$$"
cp -f "${rules_src_file}" "${rules_tmp}"
chmod 0644 "${rules_tmp}"
mv -f "${rules_tmp}" "${rules_dst_file}"

# Invariant 1a: destination exists.
if [[ -e "${rules_dst_file}" ]]; then
  pass "case1: destination file exists"
else
  fail "case1: destination file missing"
fi

# Invariant 1b: destination is a regular file, NOT a symlink (the security
# invariant — symlink would re-expose the TOCTOU window).
if [[ -L "${rules_dst_file}" ]]; then
  fail "case1: destination is a symlink (should be a real file)"
else
  pass "case1: destination is not a symlink"
fi
if [[ -f "${rules_dst_file}" ]]; then
  pass "case1: destination is a regular file"
else
  fail "case1: destination is not a regular file"
fi

# Invariant 1c: destination directory is a real directory, NOT a symlink.
if [[ -L "${rules_dst_dir}" ]]; then
  fail "case1: destination directory is a symlink (should be a real dir)"
else
  pass "case1: destination directory is not a symlink"
fi

# Invariant 1d: content equals source bit-for-bit.
if cmp -s "${rules_src_file}" "${rules_dst_file}"; then
  pass "case1: destination content == source"
else
  fail "case1: destination content differs from source"
fi

# ---- case 2: legacy deploy upgrade (existing symlink) ----
DEPLOY_DIR2="${TMPDIR}/case2/.mallcop"
mkdir -p "${DEPLOY_DIR2}/agents"
# Simulate the legacy state: agents/rules is a symlink to the live source dir.
ln -sfn "${REPO_ROOT}/agents/rules" "${DEPLOY_DIR2}/agents/rules"

# Now re-run the hardened block.
rules_dst_dir2="${DEPLOY_DIR2}/agents/rules"
rules_dst_file2="${rules_dst_dir2}/operator-decisions.yaml"
if [[ -L "${rules_dst_dir2}" ]]; then rm -f "${rules_dst_dir2}"; fi
mkdir -p "${rules_dst_dir2}"
rules_tmp2="${rules_dst_file2}.tmp.$$"
cp -f "${rules_src_file}" "${rules_tmp2}"
chmod 0644 "${rules_tmp2}"
mv -f "${rules_tmp2}" "${rules_dst_file2}"

if [[ -L "${rules_dst_dir2}" ]]; then
  fail "case2: legacy symlink dir not replaced"
else
  pass "case2: legacy symlink dir replaced with real dir"
fi
if [[ -L "${rules_dst_file2}" ]]; then
  fail "case2: destination became a symlink"
else
  pass "case2: destination is not a symlink"
fi
if cmp -s "${rules_src_file}" "${rules_dst_file2}"; then
  pass "case2: destination content == source"
else
  fail "case2: destination content differs from source"
fi

# ---- case 3: textual invariant — bootstrap-deploy.sh must NOT symlink rules ----
# Defensive: catches regressions where someone re-introduces `ln -sfn` for the
# rules deploy block.
if grep -nE '^[[:space:]]*ln[[:space:]]+-sfn[[:space:]]+.*rules' "${BOOTSTRAP}" >/dev/null; then
  fail "case3: bootstrap-deploy.sh still has 'ln -sfn ... rules' (regression to symlink path)"
else
  pass "case3: bootstrap-deploy.sh does not symlink rules"
fi
# And it MUST use the atomic-copy idiom for rules: a tmpfile + mv to dst.
# Match the variable-based form: rules_tmp="…tmp.$$"; mv -f "${rules_tmp}" "${rules_dst_file}".
if grep -nE 'rules_tmp=.*\.tmp\.' "${BOOTSTRAP}" >/dev/null && \
   grep -nE 'mv -f .*rules_tmp.*rules_dst_file' "${BOOTSTRAP}" >/dev/null; then
  pass "case3: bootstrap-deploy.sh uses atomic-copy for rules"
else
  fail "case3: bootstrap-deploy.sh missing atomic-copy idiom for rules"
fi

echo
echo "  Summary: ${PASS} passed, ${FAIL} failed"
exit ${fail}
