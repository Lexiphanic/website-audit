# Lexiphanic Audit — client-audit-lexiphanic-co-uk

**Lexiphanic Audit** is a public website audit at
`audit.lexiphanic.co.uk`. Enter a domain and get an evidence-based snapshot of
the site as it is today: HTTPS and the certificate, www/apex canonicalisation,
metadata, HSTS, `llms.txt`, `security.txt`, well-known files, security headers,
email DNS, performance and the site profile. The migration conversation is
optional; the report stands on its own.

The report is the marketing asset: it is shareable, printable, and designed to
be saved as a PDF from the browser.

## URL scheme

| URL | Shows |
| --- | --- |
| `/` | The public landing page and audit form. |
| `/methodology` | Every check, weight, grade band and limitation. |
| `/reports/{domain}` | The latest report for that domain. |
| `/api/reports` | `POST` a scan (`url`, Turnstile token). |
| `/api/reports/{domain}/status` | Small JSON status payload for polling. |
| `/api/reports/{domain}` | The stored report as JSON. |
| `/health` | D1 health check for an external monitor. |

A re-run replaces the domain's stored report; the date the report was generated
is kept in `report_date` and shown in the report. Old dated links from the first
version redirect to the latest report. Report pages are `noindex`, `no-referrer`
and public; the landing page is indexable. `robots.txt` does not disallow
`/reports/` so crawlers can see the noindex rather than guessing.

## Stack

- Astro 7, `output: "server"`, `@astrojs/cloudflare`
- Tailwind CSS v4 with the same `@theme` tokens as the other Lexiphanic sites
- Cloudflare Workers, D1 and **Workflows**
- Bun (`bun` / `bunx`), never npm or npx
- Self-hosted Exo 2 and the existing Lexiphanic icon set

## Commands

```bash
bun install
bun run dev                 # astro dev (workerd + local D1)
bun run build               # astro check + astro build into dist/
bun run test                # bun test unit tests
bun run check               # astro check (the type gate)
bun run preview             # preview the built Worker

bun run db:migrate:local    # create the local D1 schema
bun run db:migrate:remote   # apply the schema to the deployed D1
bunx wrangler types         # regenerate worker-configuration.d.ts
```

There is no lint script. Verify with `bun run check`, `bun run test` and `bun run build`.

## Local development

```bash
cp .dev.vars.example .dev.vars
bun run db:migrate:local
bun run dev
```

`.dev.vars` is gitignored. With no `TURNSTILE_SECRET`, scans are accepted in
development and rejected in production. To exercise the widget locally, use the
public Turnstile test keys in `.dev.vars.example` and set `APP_ENV=development`.

`astro dev` uses the Cloudflare Vite integration, so the Workflow binding, D1
and the Rate Limiting binding run locally. The audit pipeline is a real
Workflow instance; the report page polls the D1 row while it runs.

## Configuration

### Turnstile

Create a Turnstile widget for `audit.lexiphanic.co.uk` (and `localhost` for
development), then:

- set `TURNSTILE_SITE_KEY` in `wrangler.jsonc`
- set `TURNSTILE_SECRET` as a Worker secret

Verification is fail-closed in production: a missing secret, a failed
Siteverify response, a wrong action or an unexpected hostname all reject the
scan. In development, a missing secret skips the check.

### PageSpeed Insights (optional)

Set `PSI_API_KEY` as a Worker secret to add Lighthouse scores and field Core
Web Vitals. Without it the report still completes using our own measurements and
marks Lighthouse/CWV as not run. A free Google API key is enough.

### TLS

TLS is split across two sources because a Worker cannot open a raw TLS socket to
an HTTPS host: Cloudflare's egress proxy blocks it, and `node:tls` times out or
reports that the option is not implemented. The audit therefore uses:

- **SSL Labs** (`api.ssllabs.com`) for the served certificate, protocol
  versions, cipher information and grade. A first scan can take minutes; the
  Workflow does not wait for it. The report completes with a pending grade and a
  later run picks up the cached result.
- **crt.sh** only when SSL Labs has no certificate yet (a cold cache or a scan
  still in progress). It is a fallback, with a short timeout.

SSL Labs is cached for 24 hours (`fromCache=on&maxAge=24`). If you need
zero external TLS calls later, replace `src/lib/audit/tls.ts` with a small
container running `openssl s_client`; the rest of the report does not change.

### Rate limiting

`SCAN_RATE` is a Cloudflare Rate Limiting binding: five requests per minute per
location, keyed by client IP. Turnstile is the primary bot check; the binding is
burst protection. The key is not stored.

## Deployment

Deployed as a Cloudflare Worker with static assets through **Workers Builds**.
Never run `wrangler deploy` locally: a hand-made deploy publishes a version that
matches no commit.

Build command: `bun run build`
Deploy command: `bunx wrangler deploy`
Output directory: `dist`

### Feature previews

Worker Previews do not inherit production settings. `wrangler.jsonc` therefore
has a `previews` block with a separate D1 database, preview Turnstile test keys
and a separate rate-limit namespace. The preview Worker runs audits inline
(`src/lib/workflow/inline.ts`) instead of binding to the production Workflow.

The preview database is `audit-lexiphanic-co-uk-preview`, configured in
`wrangler.preview-migrations.jsonc`. Apply migrations before deploying a preview:

```bash
bunx wrangler d1 migrations apply PREVIEW_DB --remote --config wrangler.preview-migrations.jsonc
bunx wrangler preview base-config secret put TURNSTILE_SECRET # use the Turnstile test secret
bunx wrangler preview --name <branch-name>
```

Existing previews need their secret set directly:
`bunx wrangler preview secret put TURNSTILE_SECRET --name <branch-name>`.

Preview URLs look like `<preview-name>.audit.lexiphanic.co.uk` and
`<deployment-id>.audit.lexiphanic.co.uk`. They are for review; they do not write
to production D1.

### First deploy checklist

1. Create the D1 database:

   ```bash
   bunx wrangler d1 create audit-lexiphanic-co-uk
   ```

   Put the returned `database_id` into `wrangler.jsonc`.

2. Apply the schema:

   ```bash
   bun run db:migrate:remote
   ```

3. Connect the repository in Workers Builds. The first build may fail at deploy
   until the secrets exist.

4. Set the Worker secrets:

   - `TURNSTILE_SECRET` — required for production scans.
   - `PSI_API_KEY` — optional; adds Lighthouse and Core Web Vitals.

5. Set `TURNSTILE_SITE_KEY` in `wrangler.jsonc` to the widget's public site key.

6. Attach `audit.lexiphanic.co.uk` as a Custom Domain to the Worker.

7. Turn on Cloudflare Email Sending only if you later add email; this project
   does not send mail.

The Workflow binding creates `audit-workflow` on deploy. `default_retention` is
one day on success and seven days on error; the report itself lives in D1.

## Data

`migrations/0001_init.sql` creates the first version of the table;
`migrations/0002_latest_only.sql` rebuilds it to one row per domain:

```sql
reports (
  domain, report_date, url, status, phase, progress,
  score, grade, payload_json, workflow_id, error, created_at, updated_at
)
```

`report_date` is the date the report was generated, kept for display; it is no
longer part of the URL or the uniqueness key. `payload_json` holds the report and
is capped below D1's 100 KB statement limit; labels, "why it matters" and "the
fix" live in `src/lib/audit/registry.ts` so the stored payload only carries
results and short evidence.

There are no users, no accounts, no analytics and no cookies. The only
third-party request on the landing page is Turnstile. See
[Third parties](#third-parties) and `/privacy` for the external services a scan
calls.

## Third parties

The landing page makes one third-party request: Cloudflare Turnstile. A scan
itself runs on Cloudflare and calls these services from Cloudflare's network, not
from the visitor's browser:

| Service | Used for | Required? |
| --- | --- | --- |
| Cloudflare Workers, D1, Workflows, Rate Limiting | The app itself | Yes |
| Cloudflare Turnstile | Bot check on the scan form | Yes in production |
| Cloudflare DNS over HTTPS (`cloudflare-dns.com`) | Every DNS record, email record and SSRF host check | Yes |
| Google Public DNS (`dns.google`) | DoH fallback | Only if Cloudflare DoH fails |
| RDAP.org → authoritative registry | Registrar, registration and expiry data | Yes; failures become "not checked" |
| Qualys SSL Labs | Certificate, protocols, cipher, OCSP/SCT, grade, HTTP/2 | Yes; 24 h cache, failures become "not checked" |
| crt.sh (Sectigo) | Certificate fallback | Only when SSL Labs has no certificate |
| hstspreload.org (Google/Chromium) | HSTS preload-list status | Yes; failure is a low-weight "not checked" |
| Google PageSpeed Insights | Lighthouse and CrUX scores | Optional; only with `PSI_API_KEY` |

A scan also fetches the audited site and the public URLs it references (redirect
targets, sitemaps, assets, manifest, icons, the MTA-STS policy host, sampled
links). Those hosts are outside our control, but every URL passes the SSRF
guard. Services receive the audited domain, the DNS names derived from it and
the public URLs, but not the visitor's IP address; requests originate from
Cloudflare's network.

Adding or removing an outbound service means updating this table, `AGENTS.md` and
`/privacy` together.

## Checks

`src/lib/audit/registry.ts` is the single source for check metadata. The runner
groups are in the same directory:

| File | Covers |
| --- | --- |
| `transport.ts` | redirect matrix, HSTS, homepage headers, certificate details, SSL Labs/crt.sh |
| `dns.ts` | DoH records, DNSSEC, SPF lookup budget, DKIM/DMARC/BIMI/MTA-STS/TLS-RPT, RDAP |
| `html.ts` | title, meta, Open Graph, JSON-LD, hreflang, headings, images, platform, third-party resources |
| `fingerprints.ts` | CMS, framework, analytics, consent, payments, booking, hosting and library detection |
| `third-parties.ts` | edge/CDN and DNS fingerprints, privacy categories, consent, third-party hosts |
| `files.ts` | robots.txt, sitemaps, sampled pages, llms.txt, security.txt, well-known set |
| `security.ts` | CSP, headers, cookies, SRI, forms, legal pages |
| `performance.ts` | TTFB, weight, compression, assets, CDN, PSI/CrUX |
| `migration.ts` | platform, hosting, content, email, registrar, legacy tech |
| `checks.ts` | turns facts into pass/warn/fail/info/skipped results |
| `score.ts` | weighted category scores, grade, payload trimming |

The report's **Third parties** section is informational and unscored. It names
the edge/CDN and DNS fingerprints, known advertising/analytics/session
replay/consent/chat/embed providers, and third-party hosts. It reads the
homepage and up to five sampled HTML pages from the sitemap; it does not execute
JavaScript, so tags injected by a tag manager or sent server-side may not
appear. `trackers` and `consent` are weight 0 for the same reason.

Scores are weighted pass rates: pass 1, warning 0.5, failure 0. Informational,
not-applicable and not-checked results are excluded. Grades: A 90+, B 80+,
C 70+, D 60+, E 50+, F below 50.

## Safety

- Public scan input is normalised and checked for private/reserved addresses,
  IP literals, credentials, unusual ports and blocked hostnames.
- Every redirect is re-checked before it is followed.
- Bodies are capped, timeouts are set, and no cookies or auth headers are sent.
- The scanner uses a standard browser User-Agent and no audit-specific headers.
  It does not attempt to evade blocks; if a site still blocks it, the report
  says so. It fetches a small public sample; it is not a penetration test.
- Reports are public but noindex; staff notes do not exist in this project.

## Design

The shell copies `client-lexiphanic-co-uk`: Exo 2, the plum/violet tokens,
`Ambient`, the header/footer markup and the icon set. The product wordmark is
**Lexiphanic** with a small **AUDIT** label.

Print styles are the `@media print` block in `src/styles/global.css`. The report
cover starts a new A4 page, the chrome disappears, pass rows collapse to a
single line, and warnings/failures keep their why/fix/evidence. Use Chrome or
Edge's **Print → Save as PDF**; the in-page button calls `window.print()`.

## Known limitations

- SSL Labs rate limits and first-scan latency. A report can complete with a
  pending TLS grade; the certificate from crt.sh is still shown.
- crt.sh is occasionally unavailable; it is only called when SSL Labs has no
  certificate, and its short timeout keeps the failure cheap.
- The SPF lookup count follows `include:` and `redirect=` up to ten levels but
  is an estimate: it counts `mx` as one term and does not add every A/AAAA
  lookup an MX host implies. `exp=` is excluded from the ten-lookup limit, as
  RFC 7208 requires. Void lookups are counted too and fail above two.
- Certificate lifetime is compared with the CA/Browser Forum limit for the
  certificate's issue date: 398 days before 15 March 2026, 200 days until 15
  March 2027, 100 days until 15 March 2029, then 47 days.
- Third-party and CDN detection is static. It reads the homepage and up to five
  sampled HTML pages without executing JavaScript, so GTM-injected pixels and
  server-side tags may be missed. CDN evidence is header-based and can be
  spoofed by a proxy. The performance check counts the same third-party hosts.
- Registries differ in what they expose over RDAP. `.uk` does not publish a
  transfer-lock status, so that check is marked "not checked" rather than a
  warning.
- `llms.txt`, `ai.txt` and some well-known files are emerging conventions, not
  standards. They are marked informational or low weight, never critical.
- HSTS preload status comes from `hstspreload.org`; the header's `preload` token
  only requests inclusion.
- PageSpeed Insights needs a key for reliable quota. Without it, Lighthouse and
  field CWV are explicitly "not run", not fabricated.
- The audit samples the homepage and a small set of files; it does not crawl
  the whole site.
