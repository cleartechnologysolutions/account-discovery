## Update 1.0.1 — Microsoft diagnostics

Upload the contents of this package over the existing files in your GitHub repository and commit. Keep the existing Cloudflare Worker, secrets and domain settings. Build command remains blank; deploy command remains `npx wrangler deploy`.

After the connected build succeeds, reload the site and confirm BUILD 1.0.1. Calibrate once. The Microsoft panel now shows each control result and allowlisted diagnostic fields. Copy that panel text for troubleshooting; no DevTools required.

This update improves diagnosis; it does not establish that account verification works for a given tenant. Existing conservative stop conditions and request limits remain in place. No raw upstream tokens, cookies or error bodies are displayed.

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

The Worker directly queries Microsoft's username-discovery endpoint with a random nonexistent control and your known account. It does not submit a password or attempt a token-based login.

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

Eleven automated tests passed, including execution in the actual local Workers runtime. Tests cover public-page parsing, scoped email generation, robots exclusions, private-address rejection, session authentication, cross-origin rejection, domain boundaries, rate limiting, and Microsoft control/response handling with simulated upstream data.

**No live client tenant was queried, and the app was not deployed to your account.** The live Microsoft calibration and a browser smoke test after deployment remain necessary. No guarantee of current Microsoft endpoint reliability or completeness of discovered employees is made.
