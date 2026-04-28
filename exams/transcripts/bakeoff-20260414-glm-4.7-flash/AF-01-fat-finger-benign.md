# Exam Transcript — AF-01-fat-finger-benign

## Scenario Finding (sanitized)

| Field    | Value |
|----------|-------|
| Finding  |  |
| Detector |  |
| Title    |  |
| Severity |  |

## Events

### Event evt_001

| Field      | Value |
|------------|-------|
| Timestamp  | 2026-03-10T09:02:11Z |
| Source     | azure |
| Type       |  |
| Actor      | admin-user |
| Action     | login_attempt |
| Target     | acme-corp/auth |
| Severity   | warn |

### Event evt_002

| Field      | Value |
|------------|-------|
| Timestamp  | 2026-03-10T09:02:38Z |
| Source     | azure |
| Type       |  |
| Actor      | admin-user |
| Action     | login_attempt |
| Target     | acme-corp/auth |
| Severity   | warn |

### Event evt_003

| Field      | Value |
|------------|-------|
| Timestamp  | 2026-03-10T09:03:05Z |
| Source     | azure |
| Type       |  |
| Actor      | admin-user |
| Action     | login_attempt |
| Target     | acme-corp/auth |
| Severity   | warn |

### Event evt_004

| Field      | Value |
|------------|-------|
| Timestamp  | 2026-03-10T09:03:52Z |
| Source     | azure |
| Type       |  |
| Actor      | admin-user |
| Action     | login_attempt |
| Target     | acme-corp/auth |
| Severity   | info |

## Baseline

**Known Actors:** admin-user, ci-bot, deploy-svc, org-owner

**Known Sources:** azure, github

**Frequency Tables:**

| Key | Count |
|-----|-------|
| azure:login:admin-user | 412 |
| azure:login_failure:admin-user | 8 |
| azure:login_success:admin-user | 404 |
## Actor Chain (Phase 1 placeholder)

**reasoning:** Triage escalated due to 3-failure burst. Investigation confirmed: all 4 events share IP 203.0.113.10 and identical user-agent (Mozilla/5.0 Windows NT 10.0). evt_004 login_success at 09:03:52Z follows first failure at 09:02:11Z — 101-second same-endpoint-then-success pattern is canonical credential typo. Baseline frequency (412 logins, 8 failures) confirms routine actor. No privilege expansion, no prior findings, no anomalous indicators. Credential theft test: distinguishable — attacker would not share IP and device fingerprint with legitimate user.

## Final Resolution

| Field | Value |
|-------|-------|
| action | dismiss |
| confidence | 0.92 |
| chain_action | resolved |
| triage_action | escalate |
| reasoning | Triage escalated due to 3-failure burst. Investigation confirmed: all 4 events share IP 203.0.113.10 and identical user-agent (Mozilla/5.0 Windows NT 10.0). evt_004 login_success at 09:03:52Z follows first failure at 09:02:11Z — 101-second same-endpoint-then-success pattern is canonical credential typo. Baseline frequency (412 logins, 8 failures) confirms routine actor. No privilege expansion, no prior findings, no anomalous indicators. Credential theft test: distinguishable — attacker would not share IP and device fingerprint with legitimate user. |
| finding_id | fnd_shk_210 |
| reason | admin-user failed login 3 times (evt_001–evt_003) then succeeded (evt_004) within 100 seconds, all from same IP 203.0.113.10 and same user-agent. Baseline shows 412 prior logins with 8 historical failures — this is routine fat-finger behavior, not credential compromise. |

