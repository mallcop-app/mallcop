---
name: privilege-analysis
description: "General privilege escalation reasoning — role grants, permission changes, elevation patterns"
version: "1.0"
author: mallcop@mallcop.app
---

## Privilege Analysis

### Grant vs. Use vs. Escalation

These are three distinct events that often get conflated. A **grant** is when an actor receives a permission (role attachment, policy change, group membership). A **use** is when the actor exercises that permission. **Escalation** is when the result exceeds what was explicitly intended — an actor converts a limited permission into broader access, often by chaining grants across multiple resources or principals.

Seeing a grant event in isolation tells you almost nothing. The question is whether the use that followed was proportionate to the grant, and whether the grant itself was within the actor's pre-existing authority.

Key check: did the actor who issued the grant have the authority to do so? An actor who can grant a permission they do not themselves hold is a classic privilege escalation pattern. Look for `iam:PassRole`, `iam:CreateRole`, or `iam:AttachRolePolicy` performed by actors whose own permissions do not include the downstream rights being granted.

### Elevated Window Analysis

The most important period is not the grant event — it is the window between the grant and the revocation (or the present, if no revocation has occurred).

During an elevated window, investigate every action taken by the elevated actor: what resources were accessed, what data was read or written, what new principals were created, what secondary grants were issued. An attacker who elevates privileges and then creates a new IAM user or access key before reverting has created a durable backdoor even though the elevation window looks clean at the aggregate level.

Practical steps:
1. Identify the timestamp of the elevation grant event.
2. Pull all actions by that actor from T(grant) to T(revoke) — or to the present if still elevated.
3. Look for: new principal creation, secrets access, policy changes, cross-account calls, data exports.
4. Compare the action volume and variety against the actor's baseline for the same time-of-day window.

Elevation that is fully procedural (grant, specific task, immediate revoke, no side effects) is low signal. Elevation followed by exploration, novel resource access, or secondary grants is high signal.

### Service Account vs. Human Patterns

Human actors and service accounts have fundamentally different privilege escalation risk profiles.

Human actors: escalation is usually opportunistic or credential-based. Watch for interactive sessions acquiring elevated roles, especially outside business hours or from novel source IPs. Time-bounded elevation (break-glass access, sudo sessions) is normal; unexplained persistent elevation is not.

Service accounts: escalation is usually the result of misconfiguration or supply chain compromise. A service account doing something outside its narrow function — accessing the secrets manager it doesn't normally touch, assuming a role it hasn't assumed in the baseline window — is a strong signal even if the action itself succeeds and looks authorized. Service accounts have tighter behavioral envelopes; deviations are more meaningful.

Key distinction: service account credentials that appear in human-interactive contexts (console sign-in, interactive CLI sessions with a service account key) are always anomalous.

### Approval Chain Is Not Legitimacy

A privilege grant with an approval workflow attached is not necessarily legitimate. Attackers who have already compromised an account with approval authority can manufacture legitimate-looking approvals. An approved privilege grant issued by a compromised approver is an attack, not an authorization.

When a grant is flagged as suspicious, trace the approver's own activity, not just the grantee's. Did the approver receive unusual access recently? Did the approver's account show novel source IPs or timing anomalies before issuing the approval? The approval chain is evidence of process, not evidence of legitimacy.

### Baseline Cross-Reference

The single most useful check: has this specific actor performed this specific action on this specific target resource before?

Privilege changes that are new in three dimensions simultaneously — new actor, new permission type, new target — carry the highest suspicion weight. Privilege changes where all three dimensions match baseline are low signal even if the absolute permission level is high.

The baseline window matters: a 30-day lookback is standard. For service accounts with highly regular patterns, 7 days may be sufficient. For human actors with variable schedules, 90 days reduces false positives from legitimate but infrequent tasks.

Cross-reference format: `actor:target:action` as a triple key. If this triple has count=0 in baseline, treat it as first-seen. If it has count >= threshold and last_seen is recent, treat it as known-good. The interesting cases are count=1..4 (seen before but rare) and count >= threshold with last_seen > 30 days ago (dormant pattern reactivating).
