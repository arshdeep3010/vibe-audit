# VibeAudit

**A bug finder for AI-coded "vibe apps".** Paste a snippet, or (locally) point it at a folder
or a public GitHub repo, and get a ranked, explained report of real bugs across
**security**, **logic/runtime** and **correctness/quality**, with live progress in the browser.

Built with FastAPI, an OpenAI-compatible LLM (NVIDIA Nemotron by default), Alpine.js and Three.js.
Hosted on AWS (Lambda + DynamoDB + S3 + CloudFront) with Terraform, deployed by GitHub Actions.

## Two modes

| | `APP_MODE=local` (default) | `APP_MODE=public` (for hosting) |
|---|---|---|
| Input | Snippet, local folder, GitHub repo | **Snippet only** (enforced by the server) |
| Deep scan (runs the app in Docker) | Yes | No: it would run strangers' code on your server |
| Semgrep | VibeAudit rules + Registry `p/default`; **Pro engine** with `SEMGREP_APP_TOKEN` | VibeAudit rules on the community engine (token ignored) |
| Limits | Snippet size only | Snippet size, per-visitor hourly limit, daily cap, running-scan cap |
| History | Shared list on the home page | Kept only in each visitor's browser |
| Stored results | Kept, in `data/vibeaudit.db` | Deleted after `RESULT_TTL_HOURS` (24h), in `data/vibeaudit-public.db` |
| API docs (`/docs`) | On | Off |

Public mode exists because a hosted version with folder scanning would let anyone read files on
your server, and every scan costs a model call.

## How a scan works

```
input (snippet / folder / repo)
  → map files            discover, filter, detect language, chunk large files
  → deterministic scan   secret patterns, bandit (Python), Semgrep rules; no model calls
  → triage               what is this app, which files matter        (skipped for snippets)
  → audit                one LLM call per code segment: security + logic + quality,
                         with every scanner hit in that segment passed in as a hint
  → verify               one LLM call per file: re-checks high/critical LLM findings and
                         judges every Semgrep/bandit hit (confirm or dismiss, impact, fix)
  → (deep) runtime       Docker sandbox: build, boot, HTTP and browser errors   (local only)
  → rank & grade         de-duplicate, rank by severity × confidence, grade A–F
```

### Semgrep, judged by the model

Semgrep matches code patterns: fast, free and repeatable, but noisy. VibeAudit uses it as the
first pass and lets the model be the judge:

1. **Rules.** Every scan runs [`backend/rules`](backend/rules): 42 rules written for this project
   (JavaScript/TypeScript and Python): SQL and command injection, XSS, path traversal, SSRF,
   open redirects, NoSQL injection, unverified or hard-coded JWT secrets, TLS turned off, weak
   password hashing, async `forEach`, unchecked query errors, swallowed exceptions and more.
   Each rule has `ruleid:` / `ok:` cases in `backend/rules/tests`, checked in CI with
   `semgrep --test`.
2. **Hints.** Each hit is handed to the audit prompt for its segment, so the model looks hard at
   those lines and writes its own impact and fix.
3. **Judging.** The verification call gets every Semgrep and bandit hit, labelled with its rule.
   The model confirms or dismisses each with a one-line reason, and writes the impact and fix
   for this code. Dismissed hits are left out of the grade but listed in the report with the
   reason. When the model and a rule report the same issue they merge into one finding
   marked "model + semgrep".
4. **Pro engine (self-hosted only).** With `SEMGREP_APP_TOKEN` in `.env`, local scans run
   `semgrep scan --pro`: cross-function data flow, Semgrep's Pro rules and the Registry's
   `p/default`. If the Pro engine isn't installed, the scan falls back to the community engine
   and says so in the log. Results stay on your machine; nothing is uploaded to Semgrep.

**Why the hosted demo only runs VibeAudit's rules:** Semgrep's Registry and Pro rules are
licensed for scanning your own code, not for offering to others as a service. Public mode
enforces this in code: no token, no Registry, no Pro engine, metrics off. The demo's UI shows
Semgrep Pro and the Docker sandbox as "self-hosted only".

The whole flow still costs **2 model calls per snippet**.

### Cost per snippet

A pasted snippet takes **2 model calls**: the audit (which also returns the code's profile, so
no separate triage call) and one batched verification for its high/critical findings and
scanner hits.
Earlier versions made one verification call per finding (about 12 calls for the sample).

Other cost controls:
- **Cache:** the same snippet, file name and model within `CACHE_TTL_HOURS` returns the saved
  report. That costs nothing and uses no quota, so the "Try the sample" button is free after its first run.
- **Limits (public mode):** `RATE_LIMIT_PER_HOUR` per visitor, `DAILY_SCAN_CAP` overall,
  `MAX_RUNNING_SCANS` at once, `SCAN_TIMEOUT_S` per scan.
- **Size caps:** `MAX_SNIPPET_LINES` / `MAX_SNIPPET_BYTES` / `MAX_REQUEST_BYTES`.

### Reliability

- If the model fails for every code segment, the scan ends as an **error**. It never reports a
  clean grade. If only some segments fail, the report is marked **incomplete**.
- A reply cut off by `MAX_TOKENS` keeps every complete finding. A reply that can't be parsed is
  retried once with thinking off.
- Finished jobs are evicted from memory after `JOB_RETENTION_S`. Live progress streams over SSE
  with keep-alive pings.

### Privacy & security

- Pasted code is written to a temp folder for the scan and deleted afterwards. Only the report
  is stored, and secrets in it are masked (`sk_l***tUs3`).
- **Pasted code is sent to the model provider.** Don't paste real secrets.
- Report IDs are random UUID4s (122 random bits), so a report can only be opened by someone who has its link.
- Security headers on every response (CSP, `X-Frame-Options: DENY`, `nosniff`, no referrer).
  CDN scripts are pinned with Subresource Integrity.
- LLM output is treated as untrusted: it's rendered as text, never as HTML.

## Setup

Requires **Python 3.10+** (developed on 3.13). For a Deep scan you also need **Docker Desktop**,
and **git** for GitHub scans. Both are local-only features.

```powershell
cd vibe-audit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements-dev.txt
copy .env.example .env      # then set NVIDIA_API_KEY (or LLM_API_KEY) in .env

# Semgrep, in its own environment (its pinned dependencies clash with the app's).
# The app finds .venv-semgrep on its own; set SEMGREP_APP_TOKEN in .env for the Pro engine.
python -m venv .venv-semgrep
.\.venv-semgrep\Scripts\pip install semgrep
.\.venv-semgrep\Scripts\semgrep install-semgrep-pro   # optional, after setting the token
```

> 🔐 **Rotate your API key.** The key that was in `.env` earlier was pasted into a chat and
> should be treated as leaked. Create a new one and put it in `.env` (git-ignored).

## Run

```powershell
cd backend
python -m uvicorn app.main:app --port 8000          # local mode
$env:APP_MODE="public"; python -m uvicorn app.main:app --port 8000   # try public mode
```

Then open **http://127.0.0.1:8000**. **/how-it-works** explains the pipeline, scoring, privacy
and limits for visitors, and adapts to the mode. Run a single process (no `--workers`): jobs, limits
and the cache counters live in memory.

Command line (local mode features, no limits):

```powershell
cd backend
python scan_cli.py --path ..\fixtures\buggy-sample
python scan_cli.py --paste-file ..\fixtures\snippets\express-api.js
python scan_cli.py --github https://github.com/user/repo --out report.json
python scan_cli.py --path ..\fixtures\runnable-node --depth deep    # needs Docker
```

## Tests

```powershell
cd backend
python -m pytest -q
..\.venv-semgrep\Scripts\semgrep --test --config rules rules\tests     # the rule pack
```

The tests use a fake model and mocked AWS (moto), so they need no API key, no AWS account and
make no network calls. They cover the public-mode guards, size caps, rate and daily limits, the
cache, the 2-call snippet flow, verification dropping false positives, secret masking,
truncated-JSON salvage, the "everything failed → error" rule, result expiry, job eviction, and
the Lambda path: DynamoDB store, shared limits, running-scan slots, the API → worker hand-off,
polling, the CloudFront-only origin check and the SSM key; and Semgrep: what each mode may
run (public never uses the token, Registry or Pro engine), the Pro → community fallback, scanner
hits judged by the model within the 2 calls, and (when Semgrep is installed) the rule pack
catching the sample's bugs.

## Deploy to AWS

```
browser ──HTTPS──► CloudFront ──/*──────► S3 (private, OAC)        index.html
                       │
                       └──/api/*──► Lambda "api" (function URL, IAM auth: only CloudFront can call it)
                                     │  validate · cache · rate-limit · take a slot
                                     ├──► DynamoDB  reports · cache · limits · slots · progress (TTL)
                                     └──async──► Lambda "worker"  runs the audit (≤ 6 min), writes
                                                  progress + report to DynamoDB, frees the slot
                                                  (container image from ECR, Semgrep inside)
```

Why it looks like this:
- **Lambda can't keep state between requests**, so what the server keeps in memory and SQLite
  (jobs, limits, the cache, reports) lives in one DynamoDB table, and expired items are deleted by TTL.
- **The API returns at once and a worker runs the audit.** The API invokes the worker
  asynchronously, with retries off so a failure can't bill the model twice. The browser polls
  `/api/scan/{id}/progress`, because a buffered Lambda response can't stream SSE. Locally the app still uses SSE.
- **Only CloudFront can reach the API.** The function URL uses IAM auth and CloudFront signs
  each request (origin access control). The browser sends the body's SHA-256 so POSTs can be signed.
  Per-visitor limits use `CloudFront-Viewer-Address`, which a client can't fake.
- **The worker is a container image.** Semgrep unpacks to about 290 MB, over the 250 MB limit
  for zip Lambdas, so the worker runs from an arm64 image in ECR (Semgrep in its own virtualenv).
  The API stays a 10 MB zip. The pipeline builds the image on an arm64 runner and pins the
  function to its digest; ECR keeps the last 3 images.
- **The model key lives in SSM Parameter Store** (SecureString). You create it yourself, so it
  never appears in Terraform state, GitHub or the Lambda configuration.
- **Idle cost is $0.** Everything is pay-per-request (Lambda arm64, on-demand DynamoDB, CloudFront,
  S3). The daily scan cap (100) bounds model spend. Set `BUDGET_EMAIL` for a monthly cost alert.

```
infra/
  bootstrap/      one-time: Terraform state bucket, worker image registry (ECR), and the
                  IAM role GitHub Actions assumes via OIDC
  app/            the stack: Lambda ×2, function URL, DynamoDB, S3, CloudFront, (budget)
  build_lambda.py builds build/lambda.zip (the API) with Linux arm64 wheels (works from Windows)
backend/Dockerfile  the worker image: app + Semgrep
  deploy.ps1      first deploy from your machine
.github/workflows/
  ci.yml          tests, Semgrep rule tests, terraform fmt/validate on PRs and branches
  deploy.yml      push to main → tests → worker image + API zip → terraform apply → S3 upload
                  → invalidate → smoke test
```

### First deploy (once, from your machine)

Needs the AWS CLI signed in with admin rights, Terraform ≥ 1.10 (`winget install Hashicorp.Terraform`),
the project's `.venv` and Docker Desktop (for the worker image).

1. Store the model key. Use a **new** key, since the old one leaked:
   ```powershell
   aws ssm put-parameter --name /vibeaudit/llm-api-key --type SecureString --value <your-new-key>
   ```
2. Deploy. Terraform shows each plan and asks before it changes anything:
   ```powershell
   powershell -ExecutionPolicy Bypass -File infra\deploy.ps1
   ```
   It prints the site URL and the three values for GitHub.

### After that: GitHub Actions

1. Push the project to a GitHub repo named as in `infra/bootstrap` (`github_repo`, default
   `arshdeep3010/vibe-audit`). The deploy role only trusts that repo's `main` branch and its
   `production` environment.
2. In the repo, under **Settings → Secrets and variables → Actions → Variables**, add `AWS_REGION`,
   `AWS_DEPLOY_ROLE_ARN` and `TF_STATE_BUCKET` (and optionally `BUDGET_EMAIL`). No AWS keys are stored in GitHub.
3. Every push to `main` now tests, builds, applies Terraform, uploads the frontend and smoke-tests
   `/api/health`. Pull requests run the tests and `terraform validate`.

To remove everything: `terraform destroy` in `infra/app`, then in `infra/bootstrap` (empty the
state bucket first).

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | mode, model, Semgrep engine and rule sets, limits, audits left today (public) |
| POST | `/api/scan` | `{kind, value, depth?, filename?}` → `{scan_id, cached}`; 403/413/429 with a message |
| GET | `/api/scan/{id}/events` | SSE progress stream |
| GET | `/api/scan/{id}` | full report |
| GET | `/api/scan/{id}/export?format=json\|md\|html` | download |
| GET | `/api/scans` | recent scans (local mode only) |

## Configuration

All settings live in `.env`. See `.env.example` for every key with comments. The main ones:

| Key | Default | Meaning |
|---|---|---|
| `APP_MODE` | `local` | `local` or `public` |
| `NVIDIA_API_KEY` / `LLM_API_KEY` | — | model API key (required) |
| `NVIDIA_BASE_URL` / `LLM_BASE_URL` | NVIDIA Integrate | any OpenAI-compatible endpoint |
| `MODEL` | `nvidia/nemotron-3-ultra-550b-a55b` | model id |
| `ENABLE_THINKING` | `true` | model reasoning (slower, deeper) |
| `MAX_TOKENS` | `8192` | covers reasoning + answer |
| `MAX_SNIPPET_LINES` / `MAX_SNIPPET_BYTES` | 400 / 20000 | snippet caps |
| `RATE_LIMIT_PER_HOUR` / `DAILY_SCAN_CAP` | 5 / 100 | public-mode limits |
| `RESULT_TTL_HOURS` / `CACHE_TTL_HOURS` | 24 / 24 | result expiry / cache window |
| `ENABLE_SEMGREP` | `true` | run Semgrep in the deterministic pass |
| `SEMGREP_APP_TOKEN` | — | local only: switches to the Pro engine (ignored in public mode) |
| `SEMGREP_REGISTRY_CONFIG` | `p/default` | extra Registry rules for local scans (empty = none) |

## Project layout

```
vibe-audit/
  backend/
    app/
      config.py        settings (env-driven), APP_MODE, RUNTIME (server | lambda)
      cloud.py         AWS backend for Lambda: DynamoDB store, limits, slots, progress, SSM key
      lambda_handler.py  Lambda entry points: api (Mangum) and worker
      limits.py        input validation, cache key, rate limiter
      main.py          FastAPI app: REST + SSE, guards, security headers
      jobs.py          background jobs, timeouts, eviction, SSE keep-alive
      scan.py          end-to-end orchestrator
      store.py         SQLite: reports, cache lookup, expiry
      llm/             OpenAI-compatible client (retries, JSON salvage) + prompts
      ingest/          sources (local / github / paste) + repo map / chunking
      analysis/        deterministic (secrets, bandit, Semgrep), static (LLM), verify (judge),
                       dynamic (Docker), aggregate
      models/          pydantic Finding / ScanResult
    rules/             VibeAudit's Semgrep rules + tests/ (semgrep --test cases)
    tests/             pytest suite (fake model)
    Dockerfile         worker Lambda image
    scan_cli.py        CLI runner
  frontend/index.html  single-page UI (Alpine.js + Three.js)
  infra/               Terraform (bootstrap + app), Lambda build script, first-deploy script
  .github/workflows/   CI and deploy
  fixtures/            buggy sample app, runnable Node app, sample snippet
```

## Not done yet

- Bot protection (e.g. Cloudflare Turnstile or AWS WAF). Today the per-IP and daily caps are the guard.
- A custom domain (ACM certificate + Route 53). The site uses the `*.cloudfront.net` address.
- In `RUNTIME=server` mode, limits and jobs live in memory, so run a single process. The Lambda
  runtime keeps them in DynamoDB instead.

LLM-assisted analysis can be wrong, and the number of findings varies between runs. Verify
findings before acting on them.
