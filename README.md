# Internal Audit — Information Technology Audit Application Hub

A single landing page (`index.html`) linking to three tools. **All three now run their detection logic server-side** (Azure Functions) — the browser only ever sends raw uploaded data and receives finished results back. Nothing proprietary (SOD rules, PAM privilege library, log-analysis heuristics) ships in the page source anymore.

| File | Tool | Backend |
|---|---|---|
| `index.html` | Landing dashboard (IA hub) | — |
| `sod-analyzer.html` | SOD Conflict Analyzer — Oracle Fusion & MyCom | `api/sod-analyze/` |
| `access-governance.html` | Access Governance Engine — PMWeb & Oracle Fusion PAM | `api/pam-analyze/` |
| `log-analyzer.html` | Windows Log Analyzer / LogShield | `api/log-analyze/` |
| `api/` | Azure Functions app — all three rule/heuristic engines live here | |

---

## What's hidden where

- **`api/sod-analyze/`** — the 84 Oracle SOD rules, 110 MyCom rules, alias/special-function matching, and E2E capability-area definitions.
- **`api/pam-analyze/`** — the 183-entry curated Oracle privilege library, PMWeb admin-equivalent scoring engine, and every detection function (generic/service/test account patterns, SoD combination rules, role explosion, etc.). The client-side "Privilege Library" disclosure panel that used to show these rules in the sidebar has been removed entirely — it would have defeated the purpose.
- **`api/log-analyze/`** — the regex detection patterns, scoring thresholds, and narrative generation.

Each `*.html` file now only handles: file upload, Excel/CSV parsing, column-mapping UI, chart rendering, table rendering, and Excel/PPTX/HTML export. All of that is genuinely just UI — there's no meaningful IP in "how a table renders."

---

## Option A — Azure Static Web Apps (recommended)

**Static Web Apps' free tier includes a bundled Azure Functions API at no extra cost** — this whole setup is built around that.

### Via Azure Portal (no CLI)
1. Go to the [Azure Portal](https://portal.azure.com) → **Create a resource** → **Static Web App**.
2. Choose **Other** as the deployment source (or connect a GitHub repo containing this folder).
3. Set:
   - **App location**: `/` (this folder — contains `index.html`, `sod-analyzer.html`, etc.)
   - **Api location**: `api` (this is what makes all three Function endpoints live)
   - **Output location**: leave blank (no build step needed)
4. Deploy either by connecting GitHub (Azure's Action deploys automatically on push) or via CLI (below).
5. Your hub will be live at `https://<app-name>.azurestaticapps.net/`, with the APIs automatically at `/api/sod-analyze`, `/api/pam-analyze`, and `/api/log-analyze` — same origin, no CORS config needed.

### Via CLI (fastest)
```bash
npm install -g @azure/static-web-apps-cli
swa deploy ./ --api-location ./api --env production
```

### Access control — Entra ID login required (already configured)
Every page and API endpoint now requires an authenticated, logged-in user — configured in `staticwebapp.config.json` via `"allowedRoles": ["authenticated"]` on all routes, using Azure Static Web Apps' **built-in Entra ID (Azure AD) provider**. This works out of the box on the Free tier with **no separate app registration needed** — nothing further to configure in the Azure Portal.

What this means in practice:
- Anyone hitting the site gets redirected to Microsoft's login page (`/.auth/login/aad`) before seeing anything, including the API.
- Any user in your Azure AD / Entra ID tenant can sign in by default. If you want to restrict it to *specific* people or groups (not just "anyone in the org"), that needs a custom Entra ID app registration with assigned users/groups — a bigger, separate task; say the word if you want that.
- The individual Azure Functions (`api/*/function.json`) are intentionally still set to `authLevel: "anonymous"` — this is correct, not an oversight. Azure Static Web Apps authenticates and authorizes the request at its own routing layer *before* it's ever proxied to the Function, so the Function itself doesn't need to re-check auth.
- `/login` and `/logout` are available as shortcut routes to `/.auth/login/aad` and `/.auth/logout`.

If you'd rather have the site open to anyone with the URL (no login), remove the `"allowedRoles": ["authenticated"]` entries from `staticwebapp.config.json` — but for an internal audit tool handling access-review data, keeping this on is strongly recommended.

---

## Option B — SharePoint (possible, but with real limitations)

Modern SharePoint blocks inline `<script>` execution by default. You cannot upload these files to a document library and have them run as interactive apps — SharePoint will only offer them for download.

If you still want a SharePoint presence:
- **Best option:** host on Azure (Option A) and add a SharePoint page with tiles/links to the Azure URLs.
- **Iframe embed:** SharePoint's "Embed" web part can iframe an external URL — point it at the Azure-hosted tool.
- **Not recommended:** SPFx web parts could host this natively but that's disproportionate development effort for what these tools need.

---

## Local testing before deploying

All three tools now need the API running to function. To test everything together locally:
```bash
npm install -g azure-functions-core-tools@4 @azure/static-web-apps-cli
swa start ./ --api-location ./api
```
This serves the whole hub with all three APIs wired up at `http://localhost:4280`.

To sanity-check just the engines without the browser:
```bash
node -e "const {runOracleServer}=require('./api/sod-analyze/oracle-engine'); console.log(runOracleServer({}, {}))"
node -e "const {analysePM}=require('./api/pam-analyze/engine'); console.log(typeof analysePM)"
node -e "const {runHeuristic}=require('./api/log-analyze/engine'); console.log(runHeuristic('test',['security']))"
```


