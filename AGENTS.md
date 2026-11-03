# AGENTS.md

## What this repo is

**Lexiphanic Audit** at `audit.lexiphanic.co.uk`: a public website migration
audit. It is a server-rendered Astro app on a Cloudflare Worker with D1 and a
Cloudflare Workflow. It is not the operations platform (`client-launch-lexiphanic-co-uk`)
and not a static marketing site; it shares their branding and Astro conventions.

The repository is named `client-audit-lexiphanic-co-uk`, matching the Worker in
`wrangler.jsonc`.

## Commands

```bash
bun install
bun run dev                 # astro dev on http://localhost:4321
bun run build               # astro build (the deploy build)
bun run check               # astro check (the only type gate)
bun run preview             # preview the built Worker

bun run db:migrate:local    # local D1 schema
bun run db:migrate:remote   # deployed D1 schema
bunx wrangler types         # regenerate worker-configuration.d.ts
```

Use Bun for everything. Verify with `bun run check` and `bun run build`. There is
no test or lint script; do not invent one.

**Never deploy by hand.** Workers Builds deploys on push to `main`. A manual
`wrangler deploy` publishes a version that matches no commit. Push and stop.

## Architecture

- **Astro 7, `output: "server"`**, `@astrojs/cloudflare`, Tailwind v4.
- **Custom entrypoint** `src/worker.ts` delegates requests to Astro and exports
  `AuditWorkflow`.
- **Cloudflare Workflows** (`AUDIT_WORKFLOW`) runs the audit as durable steps:
  DNS → transport/TLS → content → files → security → performance → migration →
  TLS polling → score → persist. Each step has retries; a phase that still fails
  returns a fallback so the report completes with "not checked" checks.
- **D1** (`DB`) stores one row per domain in `reports`. The full report is JSON
  in `payload_json`, capped below D1's 100 KB statement limit. `report_date` is
  the date the report was generated and is not part of the URL or uniqueness key.
- **Rate Limiting** (`SCAN_RATE`) is burst protection around the public scan
  endpoint.
- **Turnstile** verifies the scan form in production.

### Directory map

| What | Where |
| --- | --- |
| Worker entrypoint + Workflow export | `src/worker.ts` |
| Workflow pipeline | `src/lib/workflow/audit.ts` |
| Check metadata and copy | `src/lib/audit/registry.ts` |
| Facts collectors | `src/lib/audit/{dns,transport,html,files,security,performance,migration,tls}.ts` |
| Check evaluation | `src/lib/audit/checks.ts` |
| Scoring and payload trimming | `src/lib/audit/score.ts` |
| SSRF and URL normalisation | `src/lib/audit/{ssrf,normalize}.ts` |
| D1 queries | `src/lib/db.ts` |
| Turnstile | `src/lib/turnstile.ts` |
| Report loading | `src/lib/report-page.ts` |
| Report UI | `src/components/ReportView.astro` |
| Progress UI | `src/components/ReportProgress.astro` |
| Public shell | `src/layouts/BaseLayout.astro`, `src/components/layout/*` |
| Design tokens and print CSS | `src/styles/global.css` |
| Schema | `migrations/0001_init.sql` |
| Static files | `public/` |

## URL policy

`trailingSlash: "never"`. The report route is `/reports/[domain]`, which shows
the latest report. Domains are normalised to the registrable domain (strip
`www`, path, query and non-standard ports). A re-run replaces the domain's
stored report; the generated date is kept in `report_date` for display. Old
dated links redirect to `/reports/[domain]`.

Report pages set `X-Robots-Tag: noindex` and `Referrer-Policy: no-referrer` in
middleware. `robots.txt` does **not** disallow `/reports/`: crawlers need to see
the noindex. The landing page is indexable.

## Gotchas

- **`node:tls` cannot reach HTTPS hosts from Workers.** Cloudflare's egress
  proxy blocks raw TCP to HTTP services; `rejectUnauthorized` and
  `ALPNProtocols` are reported as unimplemented. TLS therefore comes from SSL
  Labs with a crt.sh certificate fallback. Do not reintroduce `node:tls` for
  public hosts.
- **SSL Labs is async.** A first scan takes about a minute. The Workflow polls
  with sleeps; the report may complete with a pending grade. SSL Labs caches for
  24 hours. It is rate-limited; handle `429` as "not checked", never a failure.
- **crt.sh is flaky.** It is a fallback for the certificate, not the only source.
- **D1's statement limit is 100 KB.** `buildReport` trims evidence and then
  large fact arrays. Keep `MAX_PAYLOAD_BYTES` in `score.ts` below 100 KB.
- **One row per domain.** `0002_latest_only.sql` rebuilds the table with
  `domain` as the primary key; do not reintroduce a date dimension or history.
- **Workflow step output limit is 1 MB.** Do not return raw HTML from a step;
  parse it inside the step.
- **Secrets are optional in `wrangler.jsonc`.** `TURNSTILE_SECRET` and
  `PSI_API_KEY` are declared in `src/env.d.ts`, not `secrets.required`, so the
  first deploy can ship without PageSpeed and with Turnstile configured later.
  Production scans refuse to run without `TURNSTILE_SECRET`; development skips
  Turnstile when it is absent.
- **`astro dev` supports the Workflow binding.** It is a real local instance.
  If that changes, use `wrangler dev` for end-to-end tests and keep `astro dev`
  for UI work.
- **Print CSS is the PDF.** The browser's print engine does not support CSS page
  numbers; do not promise them. `beforeprint` opens all `<details>`; pass rows
  are hidden in print so the PDF stays readable.
- **No analytics, no cookies, no accounts.** Do not add tracking. Turnstile is
  the only third-party request on the landing page.
- **Public scan safety.** Keep the SSRF guard (`src/lib/audit/ssrf.ts`) on every
  request and redirect. Do not add features that scan private hosts, log in,
  submit forms or test for vulnerabilities.
- **Header/footer parity.** Keep `Header.astro`, `Footer.astro`,
  `BaseHead.astro`, the tokens and Exo 2 in step with
  `client-lexiphanic-co-uk`.

## Deployment

Workers Builds from this repository:

```text
Build command:   bun run build
Deploy command:  bunx wrangler deploy
Output directory: dist
```

First deploy: create D1 (`audit-lexiphanic-co-uk`), put its id in
`wrangler.jsonc`, apply migrations, connect the repository, set
`TURNSTILE_SECRET` (and optionally `PSI_API_KEY`), set `TURNSTILE_SITE_KEY`,
then attach `audit.lexiphanic.co.uk` as a Custom Domain.

Keep `README.md` accurate for handover: commands, storage, secrets (names only),
third parties and known limitations.
