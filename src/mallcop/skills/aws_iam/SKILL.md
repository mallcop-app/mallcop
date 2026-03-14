---
name: aws-iam
parent: privilege-analysis
description: "AWS IAM investigation — trust policies, assume-role chains, service-linked roles, SCPs"
version: "1.0"
author: mallcop@mallcop.app
---

## AWS IAM Investigation

### Role Trust Policies — The Principal Field

Every IAM role has a trust policy that defines who can assume it. The `Principal` field in a trust policy statement is the actual attack surface — it answers "who is trusted to call AssumeRole on this role."

Trust policy patterns to flag:

- `"Principal": {"AWS": "*"}` — any AWS identity can assume this role. This is almost never intentional and is an immediate escalation path.
- Cross-account principals (`"arn:aws:iam::EXTERNAL_ACCOUNT_ID:root"`) that don't match known partner accounts. Attackers who compromise a role can modify its trust policy to add their own external account, then access the role from outside your environment.
- Wildcarded service principals with condition mismatches — a trust policy that allows `lambda.amazonaws.com` to assume a role but does not restrict via `aws:SourceAccount` or `aws:SourceArn` is vulnerable to confused deputy attacks from other Lambda functions.

When investigating a suspicious role assumption: always read the trust policy first. The trust policy tells you whether the assumption was within the stated authorization boundary.

### AssumeRole Chains

CloudTrail's `AssumeRole` event records the caller, the role being assumed, and the resulting session. To trace a chain:

1. Find the initial `AssumeRole` event. The `userIdentity.arn` field identifies the caller; `requestParameters.roleArn` identifies what was assumed.
2. The resulting session will have a `userIdentity.type` of `AssumedRole` and a `userIdentity.arn` of the form `arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME/SESSION-NAME`.
3. Follow subsequent API calls made by that session ARN — they will show as `AssumedRole` in `userIdentity.type`.
4. If those calls include another `AssumeRole`, you have a chain. Repeat.

The `sessionContext.sessionIssuer` field in subsequent events shows the originating role, which is how you can work backwards through a chain from a terminal action to the original caller.

**SourceIdentity**: When set, `sts:SourceIdentity` persists through AssumeRole chains and cannot be changed. If your org enforces SourceIdentity, it links all chained actions back to the original human identity. Absence of SourceIdentity in an org that requires it is a red flag.

**Session names**: The `RoleSessionName` parameter in AssumeRole calls is set by the caller and often reveals automation patterns. Unusual session names (random strings, names inconsistent with the calling system's convention) on a well-established role are worth flagging.

### Service-Linked Roles

Service-linked roles have paths starting with `/aws-service-role/` and are managed entirely by AWS. They cannot be modified by IAM users — the trust policy and attached policies are immutable. When you see `iam:CreateServiceLinkedRole` in CloudTrail, it was initiated by an AWS service action (e.g., creating a VPC peering connection triggers the VPC service to create its own role).

Service-linked roles are **not** a privilege escalation vector from the application layer. Do not flag them as suspicious based on their permission scope — AWS manages the authorization boundary. What IS worth flagging: `iam:CreateServiceLinkedRole` called from user code (vs. via AWS console/service action), which could indicate someone trying to create a backdoor using a service role as cover.

### SCPs and the Effective Permission Boundary

IAM role policies define what a principal can do. SCPs (Service Control Policies) define what the organization allows — an SCP deny overrides any role-level allow, even for the root account.

When investigating why an action succeeded or failed, check both layers. An action that looks authorized by IAM policy may be blocked by SCP. Conversely, an action that looks impossible given the apparent permissions may succeed if an SCP was recently modified to allow it.

Key investigation pattern: `AccessDenied` with `errorCode` that doesn't match the resource policy or role policy means look for an SCP. `iam:ListPoliciesGrantingServiceAccess` will show the active policy set, but SCP contents require Organization admin access — cross-reference with `organizations:DescribePolicy`.

### Key Event Types

**CreateRole** (`iam:CreateRole`): records the initial trust policy in `requestParameters.assumeRolePolicyDocument`. This is the baseline for trust policy drift — compare the policy at creation against the current state. If the trust policy was modified after creation, there will be a `UpdateAssumeRolePolicy` event.

**AttachRolePolicy** (`iam:AttachRolePolicy`): records which managed policy was attached to which role. If this event appears without a corresponding `CreateRole` in the same session, an existing role's permissions were expanded. Check whether the attaching principal had `iam:AttachRolePolicy` in their own policy.

**AssumeRole** (`sts:AssumeRole`): the event that proves a role assumption occurred. Always check: source IP (expected for this caller?), time (business hours?), MFA present in session context? AssumeRole without MFA on a sensitive role is a control gap even if it's not an active incident.

**PutRolePolicy** (`iam:PutRolePolicy`): inline policy creation or update. Unlike managed policies, inline policies do not appear in `iam:ListPolicies`. An attacker who wants to avoid detection may prefer inline policies over managed policy attachments because inline policies are less visible in default IAM views.
