# ForYouToDo.md — Manual Steps for Paid Tier Setup

These steps cannot be automated — they require human authentication, external dashboards,
or one-time token generation. Complete them in order before testing the paid tier.

---

## Phase 1 — Private Noctis-Edge-KB repository

### Step 1 · Make Noctis-Edge-KB private

1. Go to https://github.com/PearceTech335/Noctis-Edge-KB
2. Settings → General → Danger Zone → **Change repository visibility** → **Private**
3. Confirm the change.

---

### Step 2 · Create a fine-grained PAT for the GitHub Actions pipeline (`KB_PUSH_TOKEN`)

This token is used by the `build-community-kb.yml` workflow to push `community_kb.json`
into the private `Noctis-Edge-KB` repo.

1. Go to https://github.com/settings/personal-access-tokens/new
2. Set **Token name**: `Noctis-KB-Push-Token`
3. Set **Expiration**: 1 year (or your preference)
4. Under **Repository access**, choose **Only select repositories** and add:
   - `PearceTech335/Noctis-Edge-Submissions`
   - `PearceTech335/Noctis-Edge-KB`
5. Under **Permissions → Repository permissions**, set:
   - **Contents**: Read and write
   - **Issues**: Read and write  _(needed to open quarantine-alert issues)_
   - **Metadata**: Read-only _(required by GitHub)_
6. Click **Generate token** and copy the value.
7. Go to https://github.com/PearceTech335/Noctis-Edge-Submissions/settings/secrets/actions
8. Click **New repository secret**, name it `KB_PUSH_TOKEN`, paste the token, and save.

---

### Step 3 · Create a read-only PAT for the Cloudflare Worker (`GITHUB_KB_TOKEN`)

This token is used by the Cloudflare Worker to read `community_kb.json` from
`Noctis-Edge-KB` when a user presents a valid Polar license key.

1. Go to https://github.com/settings/personal-access-tokens/new
2. Set **Token name**: `Noctis-KB-Read-Token`
3. Set **Expiration**: 1 year (or your preference)
4. Under **Repository access**, choose **Only select repositories** and add:
   - `PearceTech335/Noctis-Edge-KB`
5. Under **Permissions → Repository permissions**, set:
   - **Contents**: Read-only
   - **Metadata**: Read-only _(required by GitHub)_
6. Click **Generate token** and copy the value.
7. Add it to Cloudflare as a Worker secret:
   ```bash
   cd /home/alfred/Projects/Noctis-Edge/cloudflare
   wrangler secret put GITHUB_KB_TOKEN
   # Paste the token when prompted
   ```

---

## Phase 2 — Push the submissions pipeline to Noctis-Edge-Submissions

The `submissions-pipeline/` directory in this repo contains the GitHub Actions workflows
and scripts that must live in the `PearceTech335/Noctis-Edge-Submissions` repository.

Run the following commands once:

```bash
# Clone the submissions repo alongside Noctis-Edge
git clone https://github.com/PearceTech335/Noctis-Edge-Submissions.git /tmp/submissions

# Copy the pipeline files
cp -r /home/alfred/Projects/Noctis-Edge/submissions-pipeline/scripts \
       /tmp/submissions/
cp -r /home/alfred/Projects/Noctis-Edge/submissions-pipeline/.github \
       /tmp/submissions/

# Commit and push
cd /tmp/submissions
git add scripts/ .github/
git commit -m "feat: add submission validation and community KB build pipeline"
git push origin main
```

---

## Phase 3 — Polar.sh product and license configuration

### Step 4 · Create the Noctis-Edge KB product on Polar.sh

1. Go to https://polar.sh
2. Log in with your **PearceTech335** account.
3. Navigate to **Products** → **New product**
4. Fill in:
   - **Name**: Noctis Edge Community Intelligence KB
   - **Description**: Monthly subscription granting access to the community-curated CVE knowledge base, including verified exploitation scripts and remediation notes.
   - **Pricing**: Set your desired monthly price (e.g. $4.99/month)
5. Click **Add benefit** → **License Keys**
6. Configure the license key benefit:
   - **Limit activations**: 3  _(one per device, up to 3 devices)_
   - **Usage limit**: _(leave empty — unlimited API calls)_
   - **Expires**: _(leave empty — does not expire while subscription is active)_
7. Save the product.

---

### Step 5 · Obtain Polar.sh credentials for the Cloudflare Worker

#### Organisation ID (`POLAR_ORGANIZATION_ID`)

1. In Polar.sh, go to **Settings → Organisation**
2. Copy the **Organisation UUID** (looks like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

#### API Token (`POLAR_ORG_ACCESS_TOKEN`)

1. In Polar.sh, go to **Settings → API → New token** (or Developer → Access Tokens)
2. Set the scope to include **`license_keys:write`** (read + validate)
3. Copy the generated token.

---

### Step 6 · Deploy Polar secrets + redeploy the Cloudflare Worker

```bash
cd /home/alfred/Projects/Noctis-Edge/cloudflare

# Add the Polar secrets
wrangler secret put POLAR_ORG_ACCESS_TOKEN
# Paste the token when prompted

wrangler secret put POLAR_ORGANIZATION_ID
# Paste the organisation UUID when prompted

# Redeploy the Worker (includes the new /community-kb route)
wrangler deploy
```

---

## Phase 4 — User-facing: set KB_LICENSE_KEY in noctis.conf

Once a user subscribes on Polar.sh and receives their license key:

1. Open `noctis.conf` (in the Noctis-Edge install directory)
2. Add or update the line:
   ```ini
   KB_LICENSE_KEY=XXXX-XXXX-XXXX-XXXX
   ```
3. The next run of **Update** will pull and merge the community KB automatically.

---

## Verification Checklist

Work through this after completing all steps above:

- [ ] `Noctis-Edge-KB` repository is **private** on GitHub
- [ ] `KB_PUSH_TOKEN` secret is set on `Noctis-Edge-Submissions`
- [ ] `GITHUB_KB_TOKEN` Cloudflare secret is set
- [ ] `POLAR_ORG_ACCESS_TOKEN` and `POLAR_ORGANIZATION_ID` Cloudflare secrets are set
- [ ] `wrangler deploy` completed without errors
- [ ] Worker health check passes: `curl https://noctis-kb-relay.pearcetechnologies1.workers.dev/health`
- [ ] Invalid key rejected: `curl -X POST .../community-kb -d '{"license_key":"bad"}' -H 'Content-Type: application/json'` returns 403
- [ ] Valid key accepted: same request with a real Polar key returns the community KB JSON
- [ ] `submissions-pipeline/` workflows appear in `Noctis-Edge-Submissions` Actions tab
- [ ] Pushing a test `.json` submission triggers the validate workflow
- [ ] `update.sh` curl path works end-to-end with a valid `KB_LICENSE_KEY` in `noctis.conf`
