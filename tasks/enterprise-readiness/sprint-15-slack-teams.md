# Sprint 15 — Slack / Teams webhook alerts

**Phase:** 5.3 | **Estimate:** 2 days | **Risk:** Low | **Ships:** v0.13.1
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §13 (no real-time alerts today)

---

## Why

Security teams want CRITICAL findings to page them in Slack or Teams. This sprint adds incoming-webhook alerts from `fendix serve` after job completion.

**Prerequisite:** Sprint 07 (`fendix serve`).

---

## Read first

- [Sprint 14 (Jira)](sprint-14-jira.md) — same hook point (post-scan-complete in serve)
- Slack incoming webhooks: https://api.slack.com/messaging/webhooks
- Teams incoming webhooks: https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook

---

## Config

```yaml
integrations:
  notify:
    slack_webhook_url: ""    # https://hooks.slack.com/services/...
    teams_webhook_url: ""    # https://outlook.office.com/webhook/...
    min_severity: CRITICAL
    dedup_window_hours: 1
```

## Behaviour

After scan completion, for each finding ≥ `min_severity`:
- If `slack_webhook_url` set → POST a Slack Block Kit message
- If `teams_webhook_url` set → POST a Teams Adaptive Card
- Both can be set; both fire independently

## Rate limiting / dedup

In-memory `map[finding.ID]time.Time`. Suppress alert if `time.Since(lastAlerted[id]) < dedup_window_hours`. Reset on process restart (documented limitation).

## Slack payload

```json
{
  "blocks": [
    {"type": "section", "text": {"type": "mrkdwn",
      "text": "*🔴 Fendix: New CRITICAL finding*\n*{title}*\n`{endpoint}`"}},
    {"type": "section", "fields": [
      {"type": "mrkdwn", "text": "*Severity:* CRITICAL"},
      {"type": "mrkdwn", "text": "*Confidence:* {confidence}"}
    ]},
    {"type": "section", "text": {"type": "mrkdwn", "text": "*Fix:*\n{fix}"}},
    {"type": "context", "elements": [
      {"type": "mrkdwn", "text": "Fendix ID: `{id}` · Job: `{jobID}`"}
    ]}
  ]
}
```

## Teams Adaptive Card

```json
{
  "type": "message",
  "attachments": [{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "content": {
      "type": "AdaptiveCard",
      "version": "1.3",
      "body": [
        {"type": "TextBlock", "size": "Medium", "weight": "Bolder",
         "text": "🔴 Fendix: New {severity} finding", "color": "Attention"},
        {"type": "TextBlock", "text": "{title}", "wrap": true},
        {"type": "FactSet", "facts": [
          {"title": "Endpoint:", "value": "{endpoint}"},
          {"title": "Confidence:", "value": "{confidence}"},
          {"title": "Fendix ID:", "value": "{id}"}
        ]},
        {"type": "TextBlock", "text": "**Fix:** {fix}", "wrap": true}
      ]
    }
  }]
}
```

## Package layout

```
go/internal/integrations/notify/
  notify.go         — Notifier interface, dedup map
  slack.go          — Slack-specific marshaller
  teams.go          — Teams-specific marshaller
  notify_test.go
  slack_test.go
  teams_test.go
```

## Tests

```go
// TestSlackPayloadShape_MatchesBlockKit
// TestTeamsPayloadShape_MatchesAdaptiveCard
// TestNotifier_SkipsBelowMinSeverity
// TestNotifier_DedupWithinWindow
// TestNotifier_DedupExpiresAfterWindow
// TestNotifier_SlackOnly
// TestNotifier_TeamsOnly
// TestNotifier_BothEnabled_BothCalled
// TestNotifier_SlackErrorDoesNotBlockTeams (independent error handling)
// TestNotifier_HTTP4xx_DoesNotPanic
```

## CHANGELOG

```markdown
### Added (v0.13.1)

- **Slack / Teams alerts** for `fendix serve`. After scan completion,
  fendix posts a message per CRITICAL finding (configurable severity
  threshold) to the configured incoming webhook(s). Both Slack and
  Teams supported; can be enabled independently.

  Dedup: an in-memory map suppresses repeat alerts for the same
  finding ID within `dedup_window_hours` (default 1h). Resets on
  process restart.

  Config: `integrations.notify.{slack_webhook_url, teams_webhook_url,
  min_severity, dedup_window_hours}` in `.fendix.yaml`.
```

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Slack rate-limits webhook at 1 req/s per webhook | Low | Dedup naturally throttles; if customer adds 100 findings at once, in-memory queue serialises. |
| Teams Adaptive Card schema changes (1.3 → 1.5) | Low | Pin to 1.3 (widely supported). Schema version visible in payload. |
| Process restart loses dedup state → re-alert spam | By-design | Documented. Sprint 15.5 could persist via SQLite (Sprint 07.5 prerequisite). |
| Webhook URL accidentally checked into git | Med | Add a `.fendix.yaml` linter warning if webhook URLs look like real Slack hosts. Out of scope. |

## Definition of done

Standard DoD plus:
- 10+ unit tests
- Manual end-to-end against a real Slack workspace + real Teams team (record in PR)
- README updated with config example

## Follow-ups

- **Sprint 15.5:** Persistent dedup state (depends on Sprint 07.5 SQLite)
- **Sprint 15.6:** Daily/weekly digest mode — batch multiple findings into one message
- **Sprint 15.7:** PagerDuty integration

## Status

**Not started.**
