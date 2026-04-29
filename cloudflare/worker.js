/**
 * Noctis Edge — CVE KB Submission Relay
 * Cloudflare Worker
 *
 * Receives CVE knowledge base submissions from Noctis Edge users and writes
 * them to the GitHub submissions repository.  The GitHub token lives in
 * Cloudflare Secrets — it never touches a user's machine.
 *
 * Environment bindings required (set before deploying):
 *   GITHUB_TOKEN           (Secret)  PAT with contents:write on Noctis-Edge-Submissions
 *   GITHUB_KB_TOKEN        (Secret)  PAT with contents:read on Noctis-Edge-KB (private)
 *   POLAR_ORG_ACCESS_TOKEN (Secret)  Polar.sh API token (license_keys:write scope)
 *   POLAR_ORGANIZATION_ID  (Secret)  Polar.sh organisation UUID
 *   RATE_LIMIT_KV          (KV)      Namespace for per-UUID rate-limit tracking
 *
 * Routes:
 *   POST /submit        Accept a KB submission
 *   POST /community-kb  Validate Polar license key and serve community_kb.json
 *   GET  /health        Liveness probe
 */

const GITHUB_OWNER    = "PearceTech335";
const GITHUB_REPO     = "Noctis-Edge-Submissions";
const GITHUB_API_BASE = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents`;

const MAX_KB_BYTES   = 10 * 1024 * 1024;  // 10 MB hard limit
const MAX_DAILY_SUBS = 4;                  // max submissions per UUID per 24 h
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;

// UUID v4 pattern
const UUID_RE    = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
// CVE ID pattern — top-level keys of every submitted KB must match this
const CVE_KEY_RE = /^CVE-\d{4}-\d+$/;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResp(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function githubHeaders(token) {
  return {
    Authorization:          `Bearer ${token}`,
    Accept:                 "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent":           "Noctis-Edge-KB-Relay/1.0",
  };
}

// ---------------------------------------------------------------------------
// Rate limiting (Cloudflare KV)
// ---------------------------------------------------------------------------

async function checkRateLimit(kv, userId) {
  const key  = `rate:${userId}`;
  const now  = Date.now();
  const raw  = await kv.get(key, { type: "json" });
  // Keep only hits within the rolling window
  const hits = Array.isArray(raw?.hits)
    ? raw.hits.filter(t => now - t < RATE_WINDOW_MS)
    : [];

  if (hits.length >= MAX_DAILY_SUBS) {
    return { allowed: false, remaining: 0 };
  }

  hits.push(now);
  // TTL matches the window so KV entries self-expire
  await kv.put(key, JSON.stringify({ hits }), { expirationTtl: 86400 });
  return { allowed: true, remaining: MAX_DAILY_SUBS - hits.length };
}

// ---------------------------------------------------------------------------
// GitHub REST helpers — optimistic create, update on conflict
// ---------------------------------------------------------------------------

async function getFileSha(filename, token) {
  const resp = await fetch(`${GITHUB_API_BASE}/${filename}`, {
    headers: githubHeaders(token),
  });
  if (!resp.ok) return null;
  const data = await resp.json();
  return data.sha ?? null;
}

async function putFile(filename, contentB64, message, token, sha = null) {
  const payload = { message, content: contentB64 };
  if (sha) payload.sha = sha;

  const resp = await fetch(`${GITHUB_API_BASE}/${filename}`, {
    method: "PUT",
    headers: { ...githubHeaders(token), "Content-Type": "application/json" },
    body:    JSON.stringify(payload),
  });
  return resp.status;
}

// ---------------------------------------------------------------------------
// Request handlers
// ---------------------------------------------------------------------------

async function handleSubmit(request, env) {
  // ── Parse body ────────────────────────────────────────────────────────────
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResp({ error: "Request body must be valid JSON" }, 400);
  }

  const { user_id, kb } = body;

  // ── Validate user_id ──────────────────────────────────────────────────────
  if (!user_id || typeof user_id !== "string" || !UUID_RE.test(user_id)) {
    return jsonResp({ error: "user_id must be a valid UUID v4" }, 400);
  }

  // ── Validate KB shape ─────────────────────────────────────────────────────
  if (!kb || typeof kb !== "object" || Array.isArray(kb)) {
    return jsonResp({ error: "kb must be a non-null JSON object" }, 400);
  }

  const invalidKeys = Object.keys(kb).filter(k => !CVE_KEY_RE.test(k));
  if (invalidKeys.length > 0) {
    return jsonResp({
      error: `Invalid top-level keys (expected CVE-YYYY-NNNNN): ${invalidKeys.slice(0, 3).join(", ")}`,
    }, 400);
  }

  // ── Size check ────────────────────────────────────────────────────────────
  const kbStr      = JSON.stringify(kb);
  const kbBytes    = new TextEncoder().encode(kbStr).length;
  if (kbBytes > MAX_KB_BYTES) {
    return jsonResp({
      error: `KB payload exceeds 10 MB limit (${(kbBytes / 1_048_576).toFixed(1)} MB received)`,
    }, 413);
  }

  // ── Rate limiting ─────────────────────────────────────────────────────────
  const rate = await checkRateLimit(env.RATE_LIMIT_KV, user_id);
  if (!rate.allowed) {
    return jsonResp({
      error: `Rate limit exceeded — max ${MAX_DAILY_SUBS} submissions per 24 hours per installation`,
    }, 429);
  }

  // ── Write to GitHub ───────────────────────────────────────────────────────
  const filename   = `${user_id}.json`;
  // btoa only handles latin-1; handle unicode safely via TextEncoder
  const contentB64 = btoa(String.fromCharCode(...new Uint8Array(new TextEncoder().encode(kbStr))));
  const ts         = new Date().toISOString();
  const message    = `kb-submission: ${user_id} ${ts}`;

  // Optimistic PUT — attempt create without a prior read
  let status = await putFile(filename, contentB64, message, env.GITHUB_TOKEN);

  if (status === 422) {
    // File already exists; fetch SHA of the user's own file, then update
    const sha = await getFileSha(filename, env.GITHUB_TOKEN);
    if (sha) {
      status = await putFile(filename, contentB64, message, env.GITHUB_TOKEN, sha);
    } else {
      return jsonResp({ error: "SHA conflict — please retry in a moment" }, 409);
    }
  }

  if (status === 200 || status === 201) {
    return jsonResp({
      status:    "ok",
      action:    status === 201 ? "created" : "updated",
      remaining: rate.remaining,
    });
  }

  // Unexpected GitHub error — log server-side, return generic message
  console.error(`[kb-relay] GitHub PUT failed HTTP ${status} for ${filename}`);
  return jsonResp({ error: `Upstream write failed (HTTP ${status}) — try again later` }, 502);
}

async function handleCommunityKB(request, env) {
  // ── Parse body ────────────────────────────────────────────────────────────
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResp({ error: "Request body must be valid JSON" }, 400);
  }

  const licenseKey = body?.license_key;
  if (!licenseKey || typeof licenseKey !== "string" || licenseKey.trim() === "") {
    return jsonResp({ error: "license_key is required" }, 400);
  }

  // ── Validate license key with Polar.sh ────────────────────────────────────
  let polarResp;
  try {
    polarResp = await fetch("https://api.polar.sh/v1/license-keys/validate", {
      method: "POST",
      headers: {
        Authorization:  `Bearer ${env.POLAR_ORG_ACCESS_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        key:             licenseKey.trim(),
        organization_id: env.POLAR_ORGANIZATION_ID,
      }),
    });
  } catch (err) {
    console.error("[community-kb] Polar validate network error:", err);
    return jsonResp({ error: "License validation temporarily unavailable — try again later" }, 503);
  }

  if (!polarResp.ok) {
    // 404 = key not found, 403 = revoked/expired — either way, deny
    return jsonResp({
      error:   "invalid_key",
      message: "License key not recognised or inactive. Subscribe at https://polar.sh/PearceTech335",
    }, 403);
  }

  const polarData = await polarResp.json();
  if (polarData?.granted !== true) {
    return jsonResp({
      error:   "key_not_granted",
      message: "License key is not active for this product. Subscribe at https://polar.sh/PearceTech335",
    }, 403);
  }

  // ── Fetch community_kb.json from private GitHub repo ─────────────────────
  const kbResp = await fetch(
    "https://api.github.com/repos/PearceTech335/Noctis-Edge-KB/contents/community_kb.json",
    {
      headers: {
        ...githubHeaders(env.GITHUB_KB_TOKEN),
        Accept: "application/vnd.github.v3.raw",
      },
    }
  );

  if (!kbResp.ok) {
    console.error(`[community-kb] GitHub fetch failed HTTP ${kbResp.status}`);
    return jsonResp({ error: "Community KB temporarily unavailable — try again later" }, 502);
  }

  const kbText = await kbResp.text();
  return new Response(kbText, {
    status:  200,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (pathname === "/health" && request.method === "GET") {
      return jsonResp({ status: "ok" });
    }

    if (pathname === "/submit" && request.method === "POST") {
      return handleSubmit(request, env);
    }

    if (pathname === "/community-kb" && request.method === "POST") {
      return handleCommunityKB(request, env);
    }

    return jsonResp({ error: "Not found" }, 404);
  },
};
