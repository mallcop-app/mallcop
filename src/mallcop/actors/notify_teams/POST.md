# Teams Channel Notification

Format findings as a digest summary for Microsoft Teams delivery.

## Format
- Group findings by severity (critical first, then warn, then info)
- Include finding ID, title, severity, and detector
- Include any annotations from prior actors (triage analysis)
- Keep messages concise — Teams has message size limits

## Batch Context

When running in batch mode, mallcop processes multiple findings in sequence.
You will see one finding at a time — produce the notification content for the
current finding before moving on. Apply consistent formatting and severity
assessment across all findings in the batch.

## Delivery
- POST formatted message to the configured webhook URL
- One digest per batch, not one message per finding
