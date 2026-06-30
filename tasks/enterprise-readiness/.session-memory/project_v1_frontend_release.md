---
name: project_v1_frontend_release
description: v1.0.0 frontend overhaul (data sync + perf + professionalism pass) — done 2026-07-01, plus two deferred follow-ups.
metadata:
  type: project
---

On 2026-07-01, after the engine **v1.0.0** release shipped (run green, 92 signed
assets, mirrored to `homebrew-fendix`), the frontend was brought to v1.0 in 11
commits: data synced to v1.0, a performance review applied, and a
"professional without noise" pass. Key outcomes:

- **Perf:** `PageHero` 3D backdrop made opt-in (dropped three.js from 16 pages);
  Arabic font `preload:false`; **all 15 public marketing/docs pages now
  statically prerendered** (added `setRequestLocale` — they were rendering
  dynamically per request); added `app/sitemap.ts` + `app/robots.ts`.
- **SEO:** `metadataBase` + title template + OG in the layout; per-page
  title/description/canonical on 15 pages.
- **Data honesty (Rule 5):** performance page **re-benchmarked at v1.0.0** with
  real numbers (`scripts/bench/coldstart.py`, N=30, darwin/arm64) — not
  relabeled; synthetic accuracy **F1=1.000 re-verified** at v1.0.0
  (`scripts/accuracy/run.py`); **removed the unmeasured "~70% noise reduction"
  landing claim** — BENCHMARKS.md flags correlation FP-reduction as "mechanism,
  not measured reduction". Stripped version-archaeology (`new in v0.18`, etc.)
  and de-jargoned the changelog (TASK-NNN/Sprint/Phase → prose, facts kept).

**Deferred follow-ups (not in code yet):**
1. **Pricing server-render (P3):** `app/[locale]/pricing/page.tsx` is a
   `"use client"` component, so it can't export `metadata` and isn't SSG. Split
   a server shell (exports metadata, `setRequestLocale`) + a client island for
   the interactive plan grid to get per-page metadata + static rendering.
2. **/releases + /changelog fetch is >2MB:** `app/lib/releases.ts` `RELEASES_URL`
   pulls the full mirror releases JSON (~3.6MB, 92 assets × many releases) —
   over Next's 2MB data-cache limit, so the build logs "Failed to set data
   cache" and each ISR revalidation re-fetches it all. Add `?per_page=N` (e.g.
   30) to get it under 2MB and cacheable. Verify it still lists every release
   shown on /releases.

Note: the **Juice Shop DAST benchmark on /accuracy is still stamped v0.11.0**
(needs a Docker re-run to refresh to v1.0; honestly version-labeled meanwhile).
See [[project_fendix_overview]] and [[feedback_fendix_sprint_shipping_pattern]].
