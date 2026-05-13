# Cross-sprint risk register

Risks that span multiple sprints or grow over time. Per-sprint risks
live in the sprint files; this is for risks that aren't owned by any
single sprint.

| Risk | Likelihood | Severity | Owner | Mitigation |
|---|---|---|---|---|
| OSV.dev's API evolves between sprints (response shape, rate limits) | Med | Med | Sprint 02 + 09 | Pin against the schema observed at sprint start. Re-test on each release. |
| pip-audit JSON schema breaks again | Med | Low | Sprint 01 | Schema-version detection in `parsePipAuditJSON`. Clear error on mismatch. |
| Customer asks for SAML SSO mid-Phase-3 | High | Med | Sprint 08 | Documented in Sprint 08 as out-of-scope. Track in DECISIONS.md if it comes up. |
| Translation review for Arabic strings never happens, ship with TRANSLATION_REVIEW_NEEDED markers in production | Med | High | Sprint 10 | Sprint 10's DoD requires a glossary file. Block v0.13.0 stable release on review (not v0.13.0-rc). |
| GitHub App rate limits us in production at scale | Low | Med | Sprint 13 | 5000 req/hr per installation is generous; if hit, add caching to installation tokens (1h TTL). |
| Jira customer's project is non-standard (custom workflow, no "Done" transition, ADF-only description) | High | Med | Sprint 14 | Per-project config: `resolve_transition_name`, ADF auto-wrap fallback. Test against 2 different real Jira instances. |
| Semgrep installed version on customer CI ≠ schema we shipped | Med | Low | Sprint 18 | `metadata.fendix-semgrep-min-version` in each rule; gate behind a version check in `scanner.go`. |
| Performance regression hidden by `make bench` measuring the wrong thing | Med | Med | All sprints | `make bench` covers SAST throughput on a 100k-LOC fixture. Each sprint must add a fixture for its new engine if applicable. |
| Plan goes stale because sprints get reprioritised mid-flight | High | Low | Plan owner | Each sprint file has a Status section. Mark in-progress / blocked / done as work happens. Don't let zombie sprints linger. |
| External evaluator looks at this plan and concludes "this team is over-promising" | Med | High | Plan owner | Plan is honest about deferred sprints and cut features. Marketing material should reflect what's SHIPPED, not what's PLANNED. |

---

When a risk materialises or is closed:
- Update the entry with the date and outcome
- If it spawned a follow-up sprint, link it
- If it should've been caught at planning time, note the lesson here

(Add new risks below.)
