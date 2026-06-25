---
name: gotcha-fendix-shared-dev-preprod-rds
description: Local dev Docker and PreProduction share ONE RDS — local `migrate` mutates the staging DB
metadata:
  type: project
---

# Local dev and PreProduction share the same RDS

The local Docker `fendix_django` container connects to
`fendix-dev-db.cjscya0gyyid.eu-south-1.rds.amazonaws.com` / `fendix_dev_db` —
the **same** Postgres the PreProduction deploy migrates against.

**Consequence:** any `docker exec fendix_django ... python manage.py migrate`
you (or a subagent) run locally during verification is applied to the **shared
staging DB immediately**. By the time the PreProduction GitHub Actions deploy
runs its `migrate --no-input` step, it reports **"No migrations to apply"** —
not a bug, just that the migration was already applied from a local run.

**Why it matters / how to apply:**
- "No migrations to apply" in a PreProduction deploy that *introduced* new
  migrations is EXPECTED here, not a failure. Verify the schema is really in
  sync with `docker exec fendix_django ... python manage.py showmigrations <app>`
  (look for `[X]`), which reads that same RDS.
- Don't run destructive/experimental migrations locally assuming they're
  sandboxed — they hit staging. Keep migrations additive/nullable (the way
  0004_githubinstallation and 0021_scan_github_* were done).
- Confirmed 2026-06-25 while deploying the GitHub PR-scan bot (#1): 0004 +
  0021 already showed `[X]` before the deploy's migrate step ran.

Related: [[feedback-fendix-sprint-shipping-pattern]],
[[project-fendix-overview]].
