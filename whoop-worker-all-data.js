const WHOOP_AUTH_URL = "https://api.prod.whoop.com/oauth/oauth2/auth";
const WHOOP_TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token";
const WHOOP_API_BASE = "https://api.prod.whoop.com/developer";
const CALLBACK_URL = "https://whoop-oauth-fallback.polished-night-83c2.workers.dev/callback";
const SCOPES = "offline read:profile read:body_measurement read:cycles read:recovery read:sleep read:workout";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "GET") return text("Method Not Allowed", 405);

    if (url.pathname === "/oauth/start") return startOAuth(env);
    if (url.pathname === "/callback") return handleCallback(url, env);
    if (url.pathname === "/status") return status(env);

    const endpoints = {
      "/api/profile": "/v2/user/profile/basic",
      "/api/body": "/v2/user/measurement/body",
      "/api/cycles": "/v2/cycle",
      "/api/recovery": "/v2/recovery",
      "/api/sleep": "/v2/activity/sleep",
      "/api/workouts": "/v2/activity/workout",
    };

    const whoopPath = endpoints[url.pathname];
    if (!whoopPath) return text("Not Found", 404);
    if (!hasValidApiKey(request, env)) return text("Unauthorized", 401);

    return whoopGet(env, whoopPath, url.search);
  },
};

function hasValidApiKey(request, env) {
  const given = request.headers.get("x-whoop-integration-key") || "";
  const expected = env.WHOOP_INTEGRATION_KEY || "";
  if (!expected || given.length !== expected.length) return false;
  let different = 0;
  for (let i = 0; i < given.length; i++) different |= given.charCodeAt(i) ^ expected.charCodeAt(i);
  return different === 0;
}

async function startOAuth(env) {
  const state = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  await env.WHOOP_STORE.prepare(
    `INSERT INTO whoop_oauth_state (id, state, expires_at) VALUES (1, ?, ?)
     ON CONFLICT(id) DO UPDATE SET state = excluded.state, expires_at = excluded.expires_at`,
  ).bind(state, Date.now() + 600000).run();

  const authUrl = new URL(WHOOP_AUTH_URL);
  authUrl.search = new URLSearchParams({
    response_type: "code", client_id: env.WHOOP_CLIENT_ID, redirect_uri: CALLBACK_URL,
    scope: SCOPES, state,
  });
  return Response.redirect(authUrl.toString(), 302);
}

async function handleCallback(url, env) {
  if (url.searchParams.get("error")) return text("WHOOP authorization was not completed.", 400);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return text("Invalid WHOOP authorization response.", 400);

  const saved = await env.WHOOP_STORE.prepare("SELECT state, expires_at FROM whoop_oauth_state WHERE id = 1").first();
  await env.WHOOP_STORE.prepare("DELETE FROM whoop_oauth_state WHERE id = 1").run();
  if (!saved || saved.state !== state || Date.now() > saved.expires_at) return text("Authorization expired or is invalid.", 400);

  const token = await tokenRequest(new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri: CALLBACK_URL,
    client_id: env.WHOOP_CLIENT_ID, client_secret: env.WHOOP_CLIENT_SECRET,
  }));
  if (!token) return text("WHOOP token exchange failed.", 502);
  await saveTokens(env, token);
  return text("WHOOP was connected successfully. You may close this page.", 200);
}

async function status(env) {
  const token = await env.WHOOP_STORE.prepare("SELECT updated_at FROM whoop_tokens WHERE id = 1").first();
  return text(token ? "WHOOP is connected." : "WHOOP is not connected.", 200);
}

async function whoopGet(env, path, search) {
  const token = await currentToken(env);
  if (!token) return text("WHOOP is not connected.", 409);
  const response = await fetch(`${WHOOP_API_BASE}${path}${search}`, {
    headers: { Authorization: `Bearer ${token.access_token}`, Accept: "application/json" },
  });
  if (!response.ok) return text("WHOOP data request failed.", 502);
  return new Response(await response.text(), { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}

async function currentToken(env) {
  const stored = await env.WHOOP_STORE.prepare("SELECT access_token, refresh_token, expires_at FROM whoop_tokens WHERE id = 1").first();
  if (!stored) return null;
  if (Date.now() < Number(stored.expires_at) - 60000) return stored;

  const refreshed = await tokenRequest(new URLSearchParams({
    grant_type: "refresh_token", refresh_token: stored.refresh_token,
    client_id: env.WHOOP_CLIENT_ID, client_secret: env.WHOOP_CLIENT_SECRET, scope: "offline",
  }));
  if (!refreshed) return null;
  await saveTokens(env, refreshed);
  return { access_token: refreshed.access_token, refresh_token: refreshed.refresh_token, expires_at: Date.now() + Number(refreshed.expires_in) * 1000 };
}

async function tokenRequest(form) {
  const response = await fetch(WHOOP_TOKEN_URL, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body: form,
  });
  if (!response.ok) return null;
  const token = await response.json();
  return token.access_token && token.refresh_token && token.expires_in ? token : null;
}

async function saveTokens(env, token) {
  const now = Date.now();
  await env.WHOOP_STORE.prepare(
    `INSERT INTO whoop_tokens (id, access_token, refresh_token, expires_at, updated_at) VALUES (1, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET access_token = excluded.access_token, refresh_token = excluded.refresh_token, expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
  ).bind(token.access_token, token.refresh_token, now + Number(token.expires_in) * 1000, now).run();
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function text(message, status) {
  return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
}
