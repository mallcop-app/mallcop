# Slack Channel Notification

Format findings as a digest summary for Slack delivery.

## Setup

Configure `notify-slack` in `mallcop.yaml` under the `actors` section:

```yaml
actors:
  notify-slack:
    webhook_url: https://hooks.slack.com/services/T.../B.../...
```

Create a Slack incoming webhook at https://api.slack.com/messaging/webhooks:
1. Create (or select) a Slack App for your workspace.
2. Enable "Incoming Webhooks" under Features.
3. Add a new webhook and choose the channel to post to.
4. Copy the webhook URL into `mallcop.yaml`.

The webhook URL is sensitive — store it as a secret reference rather than plain text
if your mallcop.yaml is committed to version control.

## Format

- Groups findings by severity (critical first, then warn, then info)
- Uses Slack Block Kit with colored section dividers
- Includes finding ID, title, severity, detector name, and triage annotations
- Escapes `< > &` characters to prevent Slack link/mention injection

## Batch Context

When running in batch mode, mallcop processes multiple findings in sequence.
You will see one finding at a time. Produce notification content for the current
finding before moving on. Apply consistent formatting and severity assessment
across all findings in the batch. The final delivery is a single digest, not
one message per finding.

## Delivery

- POST formatted Block Kit message to the configured webhook URL
- One digest per batch run
- Deliveries are logged in the audit trail

## Troubleshooting

- **400 Bad Request**: Slack webhook rejected the payload. Check that the
  webhook URL is correct and the Slack App has not been revoked.
- **404 Not Found**: The webhook URL is stale. Regenerate it in Slack App settings.
- **channel_not_found**: The target channel was archived or deleted. Update the
  webhook to point to an active channel.
- **No notifications received**: Verify the actor is included in the escalation
  chain: `actors: [..., notify-slack]` in the relevant patrol or escalation config.
