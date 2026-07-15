# Held-out red-team corpus — design note

> Design + rationale only. The actual held-out corpus is a **closed mallcop-pro
> asset** and is deliberately NOT in this repo. This note records how it plugs
> into the agent-unreachable grader (`.github/workflows/exam.yml`) so a future
> session does not re-derive it or accidentally vendor the secret set into OSS.

## Why a held-out set at all

The public labeled corpus lives in `exams/scenarios/**` and is graded by
`mallcop exam-detect` under the `corpus.pin` sha interlock. It is the *visible*
floor: no-regression + coverage-+1 for every self-extension proposal. But a
visible corpus is also, by construction, **reachable** — a proposer (or a
poisoned build authoring Go) can read every scenario in the checkout and, in
principle, shape a change that passes exactly those cases while degrading real
detection. Goodhart's law applied to a security grader.

The defense is a **held-out, zero-tolerance, always-escalate red-team corpus**
the authoring side never sees:

- **Zero-tolerance / always-escalate:** every scenario in it is a real attack
  that MUST fire. There are no benign-twin ambiguities to argue about — a miss
  is an unambiguous RED. It is the adversarial complement to the public corpus,
  not a tuning surface.
- **Held out from the agent:** it is not in the mallcop checkout the proposer or
  opencode operates on, so it cannot be read, overfit, or edited. This is the
  same reachability property `corpus.pin` + CODEOWNERS give the public corpus,
  extended to a set the agent cannot even enumerate.

## Where it lives and how CI fetches it

- **Home:** the CLOSED mallcop-pro side — a signed release artifact (out of
  scope for this OSS repo; it is a mallcop-pro deliverable). It is versioned and
  content-addressed so a run pins an exact digest.
- **Fetch:** the required-check CI (`exam.yml`, or a mallcop-pro-side extension
  of it) fetches the corpus **read-only** as a **pinned artifact** (a specific
  release tag + sha256), into a scratch path the graded tree cannot influence.
  The fetch is a trusted, base-controlled step — it uses a read-only token
  scoped to the artifact, never a write credential, and never the PR's tree.
- **Grade:** the held-out set is graded by the **trusted, base-built** judge
  (the same `validate-proposal` / `exam-detect` binary `exam.yml` builds from
  the base ref, never from the PR tree — E5/E8). A miss on any held-out
  always-escalate scenario is a hard RED that blocks merge.

## Why this is agent-unreachable

Three independent reasons the authored branch cannot touch this judge:

1. **Not in the checkout.** The corpus is fetched from the closed side at CI
   time; it is absent from the repo the agent authors against, so the diff
   cannot add, edit, or delete a held-out scenario.
2. **Read-only, pinned.** CI pulls a signed, digest-pinned artifact with a
   read-only token. Even a full runner compromise yields no write path back to
   the corpus, and the pin means a swapped artifact fails verification.
3. **Judged by the trusted binary.** Grading runs on the base-built judge under
   `permissions: contents: read`, no secrets — the property that already makes
   the public corpus grade trustworthy (see `exam.yml` header) extends to the
   held-out set.

## Scope of THIS change

This file is the design record only. Building the closed corpus, the signed
release pipeline for it, and the mallcop-pro-side fetch/grade wiring are
mallcop-pro assets tracked separately. The OSS-side hook is already in place:
`exam.yml` builds the judge from a trusted checkout and runs it with no write
scope, so adding a held-out grade step is an additive, base-controlled change —
never something a self-extension proposal can reach.
