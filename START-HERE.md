## Update 1.0.2 — Microsoft work-account checks

1. Extract this ZIP and upload its contents over the existing files in your Account Discovery GitHub repository. Preserve the folders and commit the update.
2. Let the connected Cloudflare build finish. Keep the existing Worker, secrets, domain allowlist and Brave key. Do not delete or recreate the app. Build command stays blank; deploy command stays `npx wrangler deploy`.
3. Reload the site and confirm **BUILD 1.0.2**. Export any existing results first: reloading clears the tab's workspace.
4. Select the client domain, enter its known working Microsoft sign-in name, and click **Calibrate this domain** once. It now waits seven seconds between the two controls. Successful calibration also displays both results.
5. For internet discovery, enter the company's name and click **Search internet**. Review the names and their source links before generating addresses.

The previous version incorrectly treated every nonzero throttle status as work-account throttling. Microsoft's sign-in client defines `1` as AAD/work-account throttling and `2` as MSA/personal-account throttling. Version 1.0.2 uses a work-account request and accepts an MSA-only flag only with an explicit managed-domain result and an unambiguous 0/1 account signal. Work-account throttling, ambiguous scopes, challenges, errors, and federation still stop checks. This is still an undocumented account signal, not authoritative directory verification.

This update also disables remote passwordless credential discovery, reports inconclusive results accurately, and removes obvious navigation/sales headings from suggested employee names. Existing sessions can remain signed in, but older calibration tokens must be renewed.

The remaining sections are for first-time installation and general usage.

# Account Discovery — start here

A private tool for your authorized client assessments. No D1 database, R2 bucket, SQL setup, build command, or Microsoft application registration is required for this version.

## 1. Upload this project to GitHub

Create a **new private repository**, for example `account-discovery`.

Extract the ZIP and upload its contents. `package.json` and `wrangler.json` must appear at the repository's top level, with the `worker`, `public`, and `test` folders alongside them. Do not upload the ZIP itself or flatten the folders.

## 2. Connect it to Cloudflare

In **Workers & Pages**, create a Worker connected to that GitHub repository.

| Field | Value |
|---|---|
| Project / Worker name | `account-discovery` |
| Build command | Leave blank |
| Deploy command | `npx wrangler deploy` |
| Root directory | Repository root |

Deploy. The Worker should build without any resource IDs to replace. The included configuration creates its rate-limit bindings automatically. This is a Worker with backend code: do not use the static-files upload flow.

## 3. Add the two required settings

Open the new Worker → **Settings → Variables and Secrets → Add**.

| Name | Type | Value |
|---|---|---|
| `ADMIN_PASSWORD` | **Secret** | A new password of at least 16 characters that you choose |
| `ALLOWED_DOMAINS` | **Text** | Your authorized client domains, separated by commas, e.g. `clientone.com,clienttwo.com` |

Use plain domains without `@`, `*`, paths, or `www` unless `www` really is the email domain. Matching is exact; add another authorized email domain separately when needed.

Save/deploy the settings when Cloudflare prompts. Reload the website and sign in with your workspace password. Your old clipboard/chat password is not embedded or reused.

The configuration uses `keep_vars` so dashboard text variables survive subsequent source deployments. Secrets stay in Cloudflare; do not commit them to GitHub.

## 4. Discover accounts

1. Select the client domain.
2. Click **Discover website**. It reads up to 12 public HTML pages on the domain and its `www` host, including team/about/contact pages.
3. Review the suggested employee names. Names from headings or profiles are candidates, not confirmed current employees.
4. Add names if needed. You can paste names or import TXT/CSV files. CSV headers supported: `Name` / `Full Name` / `Display Name`, `First Name` + `Last Name`, and `Email` / `Email Address` / `UserPrincipalName`.
5. Add any known business addresses, select an email format, and click **Generate addresses**. The tool suggests a format when a name matches a sourced address.
6. Select the addresses you want to check.

Use the page field to read a specific staff page if the automatic discovery misses it. Discovery skips robots exclusions, login walls, PDFs, and pages that require JavaScript to show their content. Failed pages are recorded in the activity panel.

## 5. Turn on broader internet discovery — optional

Without an API key, the tool reads the company website and supports imports. It does **not** have an unlimited built-in internet search engine.

To enable **Search internet**, get a [Brave Search API](https://api-dashboard.search.brave.com/) key and add it to the Worker as a **Secret** named `BRAVE_API_KEY`. Check the provider's current plan and charges before enabling it. One press issues three searches, returning up to 30 results before deduplication.

Enter the company's name and click **Search internet**. It looks for published domain addresses, team pages, and search-indexed LinkedIn profiles. Possible names extracted from profile titles are added for review. The app does not sign into LinkedIn or scrape LinkedIn pages. Open the source links to check current employment and namesakes. Search snippets can be stale.

## 6. Calibrate Microsoft checks

Enter **one sign-in name you already know exists** in the selected domain, then click **Calibrate this domain**.

The Worker directly queries Microsoft's username-discovery endpoint with a random nonexistent control and your known account, with a seven-second pause between them. It does not submit a password or attempt a token-based login.

- If the two controls are distinguishable, checks unlock for 30 minutes.
- If controls fail, the app explains the issue and leaves Microsoft checks disabled. You can still discover and export addresses.
- Federated responses, challenges, unknown codes, and blocked requests are inconclusive.
- The endpoint is undocumented. Its behavior can change or be unhelpful for particular tenants. This feature is experimental, not a Microsoft-supported verification service.

Click **Check selected addresses**. It checks at most 100 addresses in one run, sequentially with about seven seconds between requests. A fresh nonexistent control is tested after every 10 addresses and at the end. If that control stops working, the last group is marked inconclusive. A blocked or ambiguous response stops the run. There are no alternate endpoint or proxy fallbacks.

“Likely exists” is an indicative account signal, not proof of an active mailbox, deliverable email, tenant membership, employment, compromise, or successful authentication. An email alias can differ from the sign-in name. For authoritative account inventory, use an authorized Microsoft Graph/Exchange export separately.

## 7. Export and retain the report

Use **Export CSV** or **Export JSON**. Exports include provenance, inference labels, evidence, method, and check timestamps. CSV export prefixes formula-like values to avoid spreadsheet formula execution.

Findings exist in the browser tab only. Reloading or closing it clears them. The browser warns before leaving a tab with findings. This first version does not have report storage, per-technician accounts, audit history, or import of exported JSON workspaces.

## 8. Optional custom address

After the `workers.dev` address works, open this Worker's **Domains → Add Domain** and enter the subdomain you choose, such as `discover.yourdomain.com`. The parent domain must already be configured appropriately in Cloudflare. Use **Add Domain** for a dedicated subdomain, not a path route.

## Updating later

Replace the project files in the same GitHub repository and commit. Let the connected Cloudflare build deploy. Do **not** delete the Worker or recreate its bindings. Keep the dashboard secrets and domain allowlist.

## What was tested before delivery

All 16 automated tests passed, including execution in the local Workers runtime. Coverage includes the managed-domain MSA-throttle regression, work-account throttle stops, calibration spacing and rate limits, safe diagnostics, name extraction, sessions, domain boundaries, and mocked Brave searches. JavaScript syntax checks passed.

One authorized live pair from the development environment returned the expected nonexistent and existing work-account signals for the supplied client domain. Both returned throttle status zero. That test used remote passwordless discovery disabled but preceded the final change to work-account-only discovery; it does not reproduce Cloudflare's outbound network or prove that the patched deployment will work there. No live Brave search or Cloudflare deployment was performed. Confirm BUILD 1.0.2 and calibrate after updating.
