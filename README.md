# Account Discovery 1.0.0

See **START-HERE.md** for the GitHub / Cloudflare dashboard deployment steps.

## Project

- `worker/index.js`: authenticated API, domain allowlist, source retrieval, search integration, calibration tokens.
- `worker/microsoft.js`: username-only Microsoft discovery and conservative tri-state interpretation.
- `public/`: vanilla browser interface; shared parsing, pattern generation, CSV encoding.
- `test/`: Node tests plus a Miniflare Worker integration test.
- `wrangler.json`: Worker, static assets, rate-limit bindings. No build step.

Runtime application dependencies: none. Wrangler is pinned for repeatable deployment, and the lockfile is included.

## Local development

```sh
npm ci
npm test
npm run dev
```

For local development only, create `.dev.vars` with a long test `ADMIN_PASSWORD`, an `ALLOWED_DOMAINS` list, and optionally `BRAVE_API_KEY`. Use HTTPS for testing the `__Host-` secure session cookie (`npx wrangler dev --local-protocol https`). Never commit secrets. Local fixtures use example addresses and mocked responses; tests do not enumerate real tenant accounts.

Deploy with `npm run deploy` or `npx wrangler deploy` after authenticating Wrangler. Cloudflare's connected GitHub flow runs the same deploy command.

## Design boundaries

The authenticated server checks the domain allowlist on every operation, including imported email checks. Auth cookies are signed, HttpOnly, Secure, SameSite=Strict, and expire after eight hours. State-changing requests require the exact page origin and JSON content type. Calibration is signed, bound to a login session and domain, and expires after 30 minutes. Rotating `ADMIN_PASSWORD` invalidates issued tokens. Logout removes the browser cookie; it does not maintain a server-side revocation list.

The app uses a single operator password. For stronger identity controls, place the app behind your organization’s existing authenticated access solution. This package does not claim to implement MFA or individual technician auditing.

Public-page retrieval accepts only HTTPS on the approved domain or its `www` host. It rejects userinfo, alternate ports, external redirects, non-public DNS answers, large bodies, and excluded robots paths. Only add domains controlled by clients you trust: DNS checks and the subsequent outbound fetch are separate resolutions, so this is not intended as an arbitrary public URL-fetching service. Sources never execute in the Worker. Browser results use text nodes rather than injected HTML.

Microsoft queries use only `https://login.microsoftonline.com/common/GetCredentialType`. Result codes 0 and 1 are treated as indicative only following successful controls; all other codes are inconclusive. Federated or throttled responses stop the UI run. There is no password testing, authentication attempt fallback, CAPTCHA solving, endpoint rotation, or proxy rotation. The rate-limit binding allows 12 checking operations per minute per domain per Cloudflare location; a calibration operation makes up to two upstream calls. Cloudflare rate limits are approximate, per-location controls, not a global transactional quota. UI checks run sequentially at a lower pace. Controls do not make undocumented endpoint behavior authoritative.

No account findings are stored server-side or written to application logs. Findings and employee names are held in tab memory; exported files contain business contact data. Cloudflare receives application traffic and may retain platform metadata according to the account configuration. Microsoft receives queried candidate usernames. Brave receives search terms if enabled. Client websites receive the public page requests. Worker observability is disabled in the supplied configuration.

No per-run billing cap is implemented for the optional search provider; the UI makes three requests per search operation. Provider keys and any charges belong to your configured account. Free Cloudflare operation is not guaranteed under all traffic volumes.

## Discovery limitations

Company HTML pages are scanned for literal addresses, mailto links, simple `[at]`/`[dot]` obfuscation, JSON-LD Person objects, and conservative staff-page heading candidates. JavaScript-only content, arbitrary PDF parsing, unrestricted web crawling, and employment verification are outside this version. Website results can include former employees, authors, and namesakes. Names require review.

Brave Search optionally supplies three query result sets: domain emails, company/team sources, and indexed LinkedIn profile snippets. The app does not use a LinkedIn account or retrieve LinkedIn profile pages. Without a search API key, broader internet discovery is unavailable; direct company-page discovery and name imports still work.

Pattern suggestions count exact name/address matches; ties remain ambiguous. Generation uses the first and last word of each supplied name, removes accents and non-ASCII punctuation, and supports common formats. Compound surnames and non-Latin names may need manual address entry. Candidate collisions are displayed. Inferred addresses stay distinct from sourced addresses even after an account signal is obtained.

## Validation

`npm test` runs the parsing/security/response tests and the Miniflare integration test. If using an existing Miniflare installation in a development environment, set `MINIFLARE_MODULE` to its ESM-importable absolute module path.

Pre-delivery checks passed: all 11 automated tests, JS syntax checks, Worker bundling, and static UI reference checks. Upstream Microsoft and Brave behavior was tested with mocks. Live Microsoft calibration against an authorized tenant and real browser interaction must be checked after deployment.

## Reference material

- [Brave Search API documentation](https://api-dashboard.search.brave.com/app/documentation/web-search/get-started)
- [Cloudflare Worker rate-limit bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)
- [Microsoft Graph supported user inventory](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0)
- [AADInternals historical research on username discovery](https://aadinternals.com/post/just-looking/) — historical behavior, not a current Microsoft API guarantee.

No third-party tool source code is bundled. The app implements its own bounded, username-only discovery client.
