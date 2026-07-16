# mallcop self-extension (CODE lane) — setup

`mallcop selfext --scaffold-gha` wrote the CODE-lane workflows into this repo
(`.github/workflows/mallcop-selfext-code.yml`, the pinned reusable workflow, and a
`CODEOWNERS` belt). This is a **BYOK (Bring-Your-Own-Key)** lane: the workflow
downloads the public OSS `mallcop` release binary and runs `mallcop selfext --run`
on **your own** inference endpoint + key — no donut/commercial rail, no `mallcop-ops`
download. The steps below are the ones GitHub will not let a scaffold do for you —
repo secrets/variables and branch protection. Do them once.

**This file is your durable copy — commit it.** The scaffolder also prints these
steps, but that output scrolls away; this file does not.

## 1. Inference endpoint + key (required — BYOK)

The lane authors on **your own** inference. Set two things:

Your inference **key** as a secret (never an admin key — the key reaches the binary
only via `--inference-key-env`, never argv):

```bash
gh secret set INFERENCE_KEY      # paste your provider/inference API key
```

Your inference **endpoint** base URL as a repo variable (a base URL is not a
credential; the egress jail resolves its host to allowlist it):

```bash
gh variable set MALLCOP_INFERENCE_URL   # e.g. https://api.anthropic.com or your gateway
```

The endpoint must be a **natively streaming** Anthropic/OpenAI-compatible inference
endpoint: the OSS `mallcop selfext` binary carries no stream-shim (unlike the retired
donut rail), and `opencode` streams unconditionally.

## 2. Author model (optional — never hardcoded)

Which model your endpoint authors with. It is **never hardcoded** — you name the model
YOUR endpoint recognizes. Set a standing default as a repo variable:

```bash
gh variable set MALLCOP_CODE_MODEL      # e.g. claude-sonnet-4, or your catalog id
```

Or override it per run via the `code_model` workflow-dispatch input (step 6). If both
are empty, the run sends the bare authoring lane and lets your endpoint pick.

## 3. CODEOWNERS

Edit `.github/CODEOWNERS`: replace `@operator` with your GitHub handle. This freezes
the committee, grader, guard, and `.github/` paths behind your review.

## 4. Pin the reusable workflow

Replace the all-zero placeholder SHA in `.github/workflows/mallcop-selfext-code.yml`
with a real `mallcop-app/selfext` release commit SHA (the caller and the reusable
workflow are a matched pair — pin a SHA where both carry this BYOK contract).
Dependabot (github-actions) can keep it current — each bump still hits your CODEOWNERS
review.

## 5. Branch protection (required — this IS the gate)

The whole safety model rests on: authored code lands as a PR that a human reviews,
and the exam check must pass before merge. Require both:

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["exam"] },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  },
  "restrictions": null
}
JSON
```

## 6. Autonomy dial (optional)

Auto-merge a clean **GREEN** authored detector. This is **config-file-only** — set it
in `mallcop.yaml`, never as a workflow input, so a web dispatch can never escalate
your blast radius:

```yaml
learning:
  autonomy: fully        # non (default) | semi | fully — fully auto-merges CODE
```

Then let GitHub honor an auto-merge request:

```bash
gh api -X PATCH repos/OWNER/REPO -f allow_auto_merge=true
```

Auto-merge still waits for step 5's required exam check, so it never bypasses the
gate. A novel-gap proposal (a finding family with no labeled coverage) always waits
for human review regardless of the dial. `semi` / `non` leave every PR for you.

## 7. Trigger an authoring run

Name the gap — the detector id and the connector event type it keys on:

```bash
gh workflow run mallcop-selfext-code.yml \
  -f detector_id=authored-deploy-burst -f event_type=github.deployment
  # optional: -f code_model=claude-sonnet-4  (override the MALLCOP_CODE_MODEL default)
```

`opencode` authors the detector on **your** endpoint + key, under an OS-enforced
Landlock jail plus a self-enforced egress firewall; the in-runner gate runs; and on
**GREEN** a review PR opens in your fork under your own identity. The workflow never
pushes to main and never merges (except the dial-gated auto-merge in step 6, which
still waits for the required exam check).

## 8. Contribute-back — share a detector upstream (optional)

After one of *your* authored detectors merges, you can propose it into the shared
open-source corpus. It needs **two** things, set once.

### a. Consent (config file, never a workflow input)

```bash
mallcop config set contribute_back on
```

This writes `learning.contribute_back: true` — **the live consent knob.** (There is a
similarly-named `sovereignty.contribute_back` field that gates **nothing**; `mallcop
config set` and the `mallcop config` summary both point you at the live one.) Consent
is config-file-only by design, so no workflow dispatch can turn it on for you.

### b. A token you control (mallcop holds none)

The upstream PR is opened under **your** identity, never mallcop's, so you provide the
credential:

1. **Fork** the OSS repo (`mallcop-app/mallcop`) under the account whose token you'll use.
2. **Mint a token** for that account — a fine-grained PAT scoped to **only that fork**,
   with **Contents: read/write** + **Pull requests: read/write** (or a classic token
   with just `public_repo`). Least privilege; it never needs anything else.
3. **Set it as a secret** on this repo:

   ```bash
   gh secret set OSS_CONTRIB_TOKEN
   ```

If you enable contribute-back but skip the token, the run does **not** fail silently —
it posts the exact fix to the run summary.

### c. Propose an already-merged detector

```bash
gh workflow run mallcop-selfext-code.yml -f promote_detector=<your-detector-name>
```

This opens a **review** PR upstream; it **never merges** — the OSS repo's own exam gate
and code-owner review decide, at every autonomy setting.
