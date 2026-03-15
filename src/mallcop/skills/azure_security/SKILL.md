---
name: azure-security
parent: privilege-analysis
description: "Azure security investigation — RBAC role assignments, Activity Log analysis, resource group scoping, Container Apps, Defender alerts"
version: "1.0"
author: mallcop@mallcop.app
---

## Azure Security Investigation

### Azure RBAC and Role Assignments

Azure RBAC uses an assignment model: a **principal** (user, group, service principal, or managed identity) is assigned a **role definition** at a **scope** (management group, subscription, resource group, or resource). The scope hierarchy is critical — a role assigned at subscription scope grants access to all resource groups and resources within it, making subscription-scope assignments far more powerful than RG-scope ones.

The four built-in roles that matter most for privilege escalation:

- **Owner**: full access including the right to assign roles to others. An actor with Owner can create new Owners.
- **Contributor**: full resource management but cannot assign roles. The boundary between Contributor and Owner is the role-assignment permission.
- **UserAccessAdministrator**: the escalation role. It grants only `Microsoft.Authorization/roleAssignments/write` — the ability to assign any role at or below its own scope. An actor with UserAccessAdministrator at subscription scope can assign themselves Owner.
- **Reader**: read-only. Flag if granted to external guest principals on sensitive RGs.

**Self-elevation is always escalate regardless of baseline history.** When `caller` in a `Microsoft.Authorization/roleAssignments/write` event matches the `principalId` in the new assignment, the actor granted themselves a role. This is a critical-severity finding even if the actor frequently manages role assignments for others — self-assignment bypasses the two-person authorization model that role management is supposed to enforce.

`Microsoft.Authorization/roleAssignments/write` is the single most important permission in Azure. Any actor who holds it at subscription scope is one API call away from full control. When investigating any Azure incident, check whether the compromised actor had this permission.

Cross-tenant risk: B2B guest accounts have UPNs ending in `#EXT#@yourtenant.onmicrosoft.com` in the Activity Log `caller` field. A guest account performing role assignments — especially at subscription scope — should be flagged immediately. Guest accounts are managed by the external organization, which means password resets and MFA enforcement are not under your control.

Custom role definitions (`Microsoft.Authorization/roleDefinitions/write`) deserve the same scrutiny as role assignments. An attacker who cannot directly assign a sensitive role may create a custom role containing `Microsoft.Authorization/roleAssignments/write` or `*/write` with a benign-sounding name, then assign themselves that role.

### Activity Log Investigation

The Activity Log records all control-plane operations in Azure. The `operationName` field follows the pattern `Microsoft.{Provider}/{ResourceType}/{Action}` — this structure lets you identify the affected service and what was done to it even without looking up documentation.

The `caller` field identifies the actor: a UPN (`user@domain.com`) for interactive human sessions, or an application ID (`{guid}`) for service principals and managed identities. A GUID caller without a corresponding display name in your environment is worth identifying — run it against your Azure AD app registrations.

`correlationId` groups all operations belonging to a single logical action. For example, deploying a Container App generates a `Microsoft.App/containerApps/write` event and several linked operations (image pull, revision creation, traffic routing update) — all sharing the same `correlationId`. When investigating a suspicious deployment, trace the full `correlationId` to understand the complete scope of what changed, not just the triggering event.

Status field interpretation: each operation produces a "Started" event and then either "Succeeded" or "Failed". **Failed operations are signal, not noise.** Repeated failures on `Microsoft.Authorization/roleAssignments/write` indicate an actor testing for permissions. A pattern of "Started" without "Succeeded" on sensitive operations indicates probing. Never filter out failed events during an investigation.

Time correlation pattern: role grant followed by resource access within minutes is the footprint of an attacker who knows what they want. The grant is the setup; the resource access is the objective. Pull Activity Log events for the actor across a 30-minute window around any suspicious role assignment.

### Service Principal Patterns

Service principals (SPs) are Azure AD objects that represent applications and automation. They authenticate with either a client secret, a certificate, or via managed identity.

Risk profile differences:
- **Client secret**: expires periodically, must be rotated. Adding a new client secret to an existing SP is a persistence technique — the attacker adds their own secret without removing the existing one, so the app continues functioning while the attacker retains access. Look for credential-add operations on SPs that predate the investigation window.
- **Certificate**: harder to exfiltrate than a secret but same concern — new certificate addition is a backdoor vector.
- **Managed identity**: Azure-managed credentials that cannot be used from outside Azure. A managed identity assignment (`Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`) is not a lateral movement vector from external attackers, but is relevant when investigating insider threats or compromised Azure workloads.

When an Activity Log entry shows a GUID caller performing role assignments, check whether that SP has recently had credentials added. Credential addition followed by role assignment from the new credential is a two-stage persistence pattern.

### Container Apps Security

Container Apps use a revision model — every deployment creates a new revision. The revision history is your deployment audit trail. `Microsoft.App/containerApps/write` is the deployment permission; who holds it on a given Container App environment is the authorization boundary question.

Scale-to-zero is normal for Container Apps — a stopped app is not a security finding. Do not flag scale-to-zero events as suspicious.

Key investigation questions for a Container App deployment:
- Did the image source change? A new registry, a new image tag that doesn't follow the normal naming convention, or a tag that cannot be found in the normal CI/CD pipeline output is suspicious.
- Were environment variables modified? `Microsoft.App/containerApps/write` events carry the full app configuration in the `properties` field. Check for new environment variables that look like credentials or C2 callback URLs.
- Was secret access involved? `Microsoft.App/containerApps/listSecrets/action` retrieves the app's secret references. This action is not normally performed by deployment pipelines — it's an interactive operation. Flag it when it appears in the Activity Log.
- Ingress changes: a Container App made externally accessible (`ingress.external: true`) or with IP restrictions removed is a new attack surface. Check `properties.configuration.ingress` in the deployment event.

### Defender Alerts

`Microsoft.Security/alerts` events in the Activity Log represent Azure Defender findings. Defender does pre-triage — severity is machine-assigned based on signal strength from telemetry you may not have direct access to (VM process trees, network flows, JIT access patterns).

Defender alert severity is a starting point, not a verdict. Defender also generates noise from legitimate operations like pentest tools, vulnerability scanners, and misconfigured apps.

**Cross-reference Defender alerts with Activity Log timeline.** A Defender alert on a storage account should be checked against Activity Log entries for that account from 24 hours before the alert. Did the actor who triggered the alert perform role assignments, credential operations, or resource modifications immediately before or after the Defender finding? Concurrent Activity Log activity and Defender alerts on the same resource is a strong correlation pattern.

**Alert suppression rules** (`Microsoft.Security/alertsSuppressionRules/write`) are a blind spot. An attacker with sufficient permissions who wants to operate undetected will create suppression rules for the alerts their activity generates. Check for suppression rule creation when investigating persistent intrusions. A suppression rule created shortly before a suspicious activity window is a strong indicator of insider knowledge of Defender's detection capabilities.

### Key Event Types for Investigation

- `Microsoft.Authorization/roleAssignments/write` — role grant (the most critical). Check: self-assignment? External principal? Subscription scope?
- `Microsoft.Authorization/roleDefinitions/write` — custom role modification. Check: new role with `*/write` or `roleAssignments/write`?
- `Microsoft.Resources/subscriptions/resourceGroups/write` — RG creation, potential new attack surface outside existing monitoring scope
- `Microsoft.KeyVault/vaults/secrets/write` — secret modification. Check: was there a preceding role grant on the Key Vault?
- `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` — identity assigned to a resource. Check: what can that identity access at subscription scope?
- `Microsoft.App/containerApps/write` — container deployment. Check: image source changed? New environment variables?
- `Microsoft.App/containerApps/listSecrets/action` — interactive secret retrieval, not a normal deployment operation
- `Microsoft.Security/alertsSuppressionRules/write` — suppression created. Check: what alert type is being silenced?

For all of these: pull the full `correlationId` group first, identify whether `caller` is a UPN or GUID, check for preceding role grant events within 30 minutes, and cross-reference with Defender alerts on the same resource within 24 hours.
