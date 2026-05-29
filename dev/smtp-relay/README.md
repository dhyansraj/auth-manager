# smtp-relay

In-cluster SMTP gateway. Accepts unauthenticated SMTP on :25 and forwards to
`smtp.sendgrid.net:587` with the platform SendGrid API key. Adds an
`X-SMTPAPI` header tagging the From-domain as `tenant` for SendGrid analytics.

## Env vars

| Name | Required | Default | Purpose |
|------|----------|---------|---------|
| `SENDGRID_API_KEY` | yes | — | SendGrid API key (SMTP password; username is the literal `apikey`) |
| `LISTEN_PORT` | no | `25` | Local listen port |

## Test

```sh
swaks --to dest@example.com --from noreply@mcp-mesh.io --server <relay-host>:25
```
