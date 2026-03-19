# Email Channel Notification

Format findings as an HTML email digest and deliver via SMTP.

## Setup

Configure `notify-email` in `mallcop.yaml` under the `actors` section:

```yaml
actors:
  notify-email:
    smtp_host: smtp.example.com
    smtp_port: 587
    smtp_user: alerts@example.com
    smtp_password: "your-smtp-password"
    from_addr: "Mallcop Alerts <alerts@example.com>"
    to_addrs:
      - security@example.com
      - on-call@example.com
```

### Common SMTP Providers

**Gmail (App Password):**
```yaml
smtp_host: smtp.gmail.com
smtp_port: 587
smtp_user: your-account@gmail.com
smtp_password: "your-app-password"  # not your login password
```
Generate an App Password at https://myaccount.google.com/apppasswords
(requires 2FA to be enabled on the Google account).

**AWS SES:**
```yaml
smtp_host: email-smtp.us-east-1.amazonaws.com
smtp_port: 587
smtp_user: "YOUR_SES_SMTP_USERNAME"
smtp_password: "YOUR_SES_SMTP_PASSWORD"
```
Create SMTP credentials in the AWS SES console under "SMTP Settings".

**SendGrid:**
```yaml
smtp_host: smtp.sendgrid.net
smtp_port: 587
smtp_user: apikey
smtp_password: "YOUR_SENDGRID_API_KEY"
```

## Format

- HTML email with findings grouped by severity (critical first, then warn, then info)
- Color-coded severity badges (red/yellow/blue)
- Includes finding ID, title, severity, detector name, and triage annotations
- From/To addresses are validated against header injection

## Batch Context

When running in batch mode, mallcop processes multiple findings in sequence.
You will see one finding at a time. Produce notification content for the current
finding before moving on. Apply consistent formatting and severity assessment
across all findings in the batch. The final delivery is a single HTML digest,
not one email per finding.

## Delivery

- Sends one HTML email per batch run via SMTP with STARTTLS on port 587
- Deliveries are logged in the audit trail

## Troubleshooting

- **Authentication failed**: SMTP credentials are wrong or expired. For Gmail,
  ensure you are using an App Password, not your account password.
- **Connection refused**: The `smtp_host` or `smtp_port` is incorrect, or the
  outbound SMTP port is blocked by a firewall.
- **Recipient rejected**: The destination address may be on a suppression list
  (AWS SES) or the domain may not be verified (SendGrid). Check your provider's
  sending dashboard.
- **No emails received**: Check spam/junk folders. Add the `from_addr` to your
  safe-senders list. Verify the actor is included in the escalation chain:
  `actors: [..., notify-email]` in the relevant patrol or escalation config.
