import { createMcpHandler } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// ── Env ───────────────────────────────────────────────────────────────────────

export interface Env {
  VAULT: KVNamespace;
  DB: D1Database;
  GITHUB_ORG: string;
  VAULT_REPO: string;
  GITHUB_TOKEN?: string;
  MCP_TOKEN_PEPPER: string;
  AI: Ai;
  ADMIN_EMAIL?: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ACCESS_TOKEN_TTL_MS  = 1000 * 60 * 60 * 8;   // 8 hours
const REFRESH_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const AUTH_CODE_TTL_MS     = 1000 * 60 * 5;         // 5 minutes
const SESSION_TTL_MS       = 1000 * 60 * 60 * 24 * 14; // 14 days
const INVITE_TTL_MS        = 1000 * 60 * 60 * 24 * 7;  // 7 days
const SESSION_COOKIE       = "km_session";
const SUPPORTED_SCOPES     = ["mcp"];
const ADMIN_EMAILS         = ["vlukereddy@gmail.com"];

function isAdmin(email: string, env?: { ADMIN_EMAIL?: string }): boolean {
  const lower = email.toLowerCase();
  if (env?.ADMIN_EMAIL && env.ADMIN_EMAIL.toLowerCase() === lower) return true;
  return ADMIN_EMAILS.includes(lower);
}

async function d1RateLimit(
  db: D1Database,
  key: string,
  maxRequests: number,
  windowMs: number
): Promise<{ allowed: boolean; retryAfterSec: number }> {
  const now = Date.now();
  const windowStart = Math.floor(now / windowMs) * windowMs;
  try {
    const result = await db.prepare(
      `INSERT INTO rate_limit_buckets (key, count, window_start) VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN window_start = excluded.window_start THEN count + 1 ELSE 1 END,
         window_start = excluded.window_start
       RETURNING count, window_start`
    ).bind(key, windowStart).first<{ count: number; window_start: number }>();
    const count = result?.count ?? 1;
    const ws = result?.window_start ?? windowStart;
    if (count > maxRequests) {
      return { allowed: false, retryAfterSec: Math.ceil((ws + windowMs - now) / 1000) };
    }
    return { allowed: true, retryAfterSec: 0 };
  } catch {
    return { allowed: true, retryAfterSec: 0 };
  }
}

function fmtDate(ts: number): string {
  return new Date(ts).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

const PROJECTS = [
  { id: "architekt", repo: "architekt", description: "Kotlin multiplatform composable architecture" },
  { id: "design", repo: "design", description: "KeckerCo design assets and system" },
  { id: "jmonorepo", repo: "jmonorepo", description: "Jesus Guardado's monorepo" },
  { id: "kecker-docs-cloudflare", repo: "kecker-docs-cloudflare", description: "Kecker docs site on Cloudflare Pages" },
  { id: "Klojure", repo: "Klojure", description: "A Clojure wrapper for KMP" },
  { id: "particular-baptists", repo: "particular-baptists", description: "Historical Particular Baptist Library — IRBS project" },
  { id: "shrink", repo: "shrink", description: "Shrink — link shortener" },
  { id: "true-confessions-compose-multiplatform", repo: "true-confessions-compose-multiplatform", description: "True Confessions Compose Multiplatform app" },
];

// ── Crypto helpers ────────────────────────────────────────────────────────────

async function hashSecret(value: string, pepper: string): Promise<string> {
  const data = new TextEncoder().encode(`${pepper}:${value}`);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomToken(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g,"")}${crypto.randomUUID().replace(/-/g,"")}`;
}

function randomClientId(): string {
  return `cli_${crypto.randomUUID().replace(/-/g,"")}`;
}

async function verifyPkce(verifier: string, challenge: string, method: string): Promise<boolean> {
  if (method !== "S256") return false;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(buf)) === challenge;
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

function isValidRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
    if (u.protocol !== "http:" && u.protocol !== "https:" && u.protocol.length > 1) return true;
    return false;
  } catch { return false; }
}

// ── Password helpers (PBKDF2-SHA256) ─────────────────────────────────────────

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // Cloudflare Workers caps PBKDF2 at 100,000 iterations
  const iterations = 100_000;
  const key = await deriveBits(password, salt, iterations);
  return `pbkdf2:${iterations}:${bufToHex(salt)}:${bufToHex(new Uint8Array(key))}`;
}

async function verifyPassword(password: string, stored: string): Promise<{ valid: boolean; needsRehash: boolean }> {
  const parts = stored.split(":");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return { valid: false, needsRehash: false };
  const iterations = parseInt(parts[1]!, 10);
  if (iterations < 1_000 || iterations > 10_000_000) return { valid: false, needsRehash: false };
  const salt = hexToBuf(parts[2]!);
  const expected = parts[3]!;
  const derived = bufToHex(new Uint8Array(await deriveBits(password, salt, iterations)));
  if (derived.length !== expected.length) return { valid: false, needsRehash: false };
  let diff = 0;
  for (let i = 0; i < derived.length; i++) diff |= derived.charCodeAt(i) ^ expected.charCodeAt(i);
  const valid = diff === 0;
  return { valid, needsRehash: valid && iterations < 100_000 };
}

async function deriveBits(password: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
}

function bufToHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return arr;
}

// ── Web sessions ──────────────────────────────────────────────────────────────

interface SessionData { user_id: string; email: string; }

async function issueSession(req: Request, env: Env, data: SessionData): Promise<Headers> {
  const sessionId = `ses_${crypto.randomUUID().replace(/-/g,"")}`;
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO web_sessions (session_id, user_id, email, created_at, expires_at) VALUES (?,?,?,?,?)"
  ).bind(sessionId, data.user_id, data.email, now, now + SESSION_TTL_MS).run();
  const h = new Headers();
  h.set("Set-Cookie", `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_MS/1000}`);
  return h;
}

async function readSession(req: Request, env: Env): Promise<SessionData | null> {
  const cookie = req.headers.get("Cookie") ?? "";
  const match = new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`).exec(cookie);
  if (!match) return null;
  const row = await env.DB.prepare(
    "SELECT user_id, email, expires_at FROM web_sessions WHERE session_id = ?"
  ).bind(match[1]).first<{ user_id: string; email: string; expires_at: number }>();
  if (!row || row.expires_at < Date.now()) return null;
  return { user_id: row.user_id, email: row.email };
}

function clearSessionHeader(): Headers {
  const h = new Headers();
  h.set("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  return h;
}

// ── OAuth token verification ──────────────────────────────────────────────────

async function authenticateAccessToken(env: Env, token: string | undefined): Promise<{ user_id: string } | null> {
  if (!token) return null;
  const hash = await hashSecret(token, env.MCP_TOKEN_PEPPER);
  const row = await env.DB.prepare(
    "SELECT user_id, expires_at, revoked_at FROM oauth_access_tokens WHERE token_hash = ?"
  ).bind(hash).first<{ user_id: string; expires_at: number; revoked_at: number | null }>();
  if (!row || row.revoked_at !== null || row.expires_at < Date.now()) return null;
  const now = Date.now();
  await env.DB.prepare("UPDATE oauth_access_tokens SET last_used_at = ? WHERE token_hash = ?").bind(now, hash).run();
  return { user_id: row.user_id };
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

const esc = (s: string) => s.replace(/[&<>'"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[c] || c);

function html(status: number, body: string, extraHeaders?: Headers): Response {
  const h = new Headers(extraHeaders);
  h.set("Content-Type", "text/html; charset=utf-8");
  h.set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  h.set("Referrer-Policy", "no-referrer");
  return new Response(body, { status, headers: h });
}

function redirect(location: string, extraHeaders?: Headers): Response {
  const h = new Headers(extraHeaders);
  h.set("Location", location);
  return new Response(null, { status: 303, headers: h });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

// ── Landing page ──────────────────────────────────────────────────────────────

const FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=EB+Garamond:ital,wght@0,400;0,500;0,600;0,700;1,400&family=Inter:wght@400;500;600&family=Nunito:wght@700&display=swap" rel="stylesheet">`;

const CSS_VARS = `:root{--bg:#FAFAFA;--surface:#FFFFFF;--surface-border:#E4E4E7;--surface-hover:#F4F4F5;--text:#18181B;--muted:#71717A;--accent:#3A3A3C;--danger:#B3261E;--danger-soft:#f9dedc;--font:'Inter',-apple-system,sans-serif}`;

function landingPage(session: SessionData | null, origin: string, env: Env): string {
  const navRight = session
    ? `<span class="nav-email">${esc(session.email)}</span><a href="/auth/logout" class="nav-ghost">Sign out</a>`
    : `<a href="/auth/login" class="nav-btn">Sign in</a>`;

  const heroCta = session
    ? `<div class="connect-section">
        <p class="connect-label">MCP Server URL</p>
        <div class="connect-box">
          <code class="connect-url">${origin}/mcp</code>
          <button class="copy-btn" onclick="navigator.clipboard.writeText('${origin}/mcp').then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)})">Copy</button>
        </div>
        <p class="connect-hint">Add this URL to Claude Desktop, claude.ai, or any MCP-compatible client.</p>
        ${isAdmin(session.email, env) ? `<p class="connect-hint" style="margin-top:8px"><a href="/admin" style="color:var(--accent);font-weight:500">Admin panel →</a></p>` : ""}
      </div>`
    : `<div class="hero-cta">
        <a href="/auth/login" class="btn-primary">Sign in</a>
      </div>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Kecker Projects</title>
${FONTS}
<style>
${CSS_VARS}
*{box-sizing:border-box}html,body{margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column}
a{color:inherit}
nav{display:flex;align-items:center;justify-content:space-between;padding:0 40px;height:64px;border-bottom:1px solid var(--surface-border);flex-shrink:0}
.brand{font-family:'Nunito',sans-serif;font-weight:700;font-size:15px;letter-spacing:0.2em;color:var(--text);text-decoration:none}
.nav-right{display:flex;align-items:center;gap:16px}
.nav-email{color:var(--muted);font-size:14px}
.nav-link{color:var(--muted);font-size:14px;font-weight:500;text-decoration:none}
.nav-link:hover{color:var(--text)}
.nav-btn{background:var(--accent);color:var(--bg);border-radius:8px;padding:8px 18px;font-size:14px;font-weight:600;text-decoration:none;transition:opacity .15s}
.nav-btn:hover{opacity:0.85}
.nav-ghost{background:transparent;border:1px solid var(--surface-border);color:var(--muted);border-radius:8px;padding:7px 14px;font-size:13px;font-weight:500;text-decoration:none}
.nav-ghost:hover{color:var(--text)}
main{flex:1}
.hero{max-width:760px;margin:100px auto 96px;padding:0 40px;text-align:center}
.eyebrow{font-size:11px;font-weight:600;letter-spacing:0.14em;text-transform:uppercase;color:var(--muted);margin:0 0 28px}
h1{font-family:'EB Garamond',serif;font-size:clamp(56px,9vw,96px);font-weight:500;line-height:1.0;margin:0 0 24px;letter-spacing:-0.01em;color:var(--text)}
h1 em{font-style:italic}
.sub{font-size:18px;color:var(--muted);line-height:1.65;margin:0 auto 44px;max-width:500px}
.hero-cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.btn-primary{background:var(--accent);color:var(--bg);border-radius:10px;padding:14px 28px;font-size:16px;font-weight:600;text-decoration:none;box-shadow:0 4px 20px rgba(58,58,60,0.22);transition:transform .15s}
.btn-primary:hover{transform:scale(1.02)}
.connect-section{max-width:460px;margin:0 auto;text-align:left}
.connect-label{font-size:11px;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
.connect-box{display:flex;align-items:center;background:var(--surface);border:1px solid var(--surface-border);border-radius:12px;padding:14px 16px;gap:12px}
.connect-url{font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-size:13px;color:var(--accent);flex:1;word-break:break-all}
.copy-btn{background:var(--accent);color:var(--bg);border:none;border-radius:8px;padding:7px 14px;font-family:var(--font);font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;transition:opacity .15s}
.copy-btn:hover{opacity:0.85}
.connect-hint{font-size:13px;color:var(--muted);margin:10px 0 0;line-height:1.55}
.divider-row{max-width:900px;margin:0 auto;padding:0 40px;display:flex;align-items:center;gap:16px;margin-bottom:40px}
.divider-text{font-size:11px;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:var(--muted);white-space:nowrap}
.divider-row::before,.divider-row::after{content:'';flex:1;height:1px;background:var(--surface-border)}
.features{max-width:900px;margin:0 auto 96px;padding:0 40px}
.features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}
.feature-card{background:var(--surface);border:1px solid var(--surface-border);border-radius:16px;padding:24px}
.feature-icon{width:38px;height:38px;border-radius:10px;background:var(--surface-hover);border:1px solid var(--surface-border);display:flex;align-items:center;justify-content:center;margin-bottom:16px;font-size:19px;line-height:1}
.feature-card h3{font-size:15px;font-weight:600;margin:0 0 8px;letter-spacing:-0.01em}
.feature-card p{font-size:13px;color:var(--muted);margin:0;line-height:1.6}
footer{border-top:1px solid var(--surface-border);padding:28px 40px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.footer-brand{font-family:'Nunito',sans-serif;font-weight:700;font-size:12px;letter-spacing:0.18em;color:var(--muted);text-decoration:none}
.footer-links{display:flex;gap:20px}
.footer-links a{font-size:13px;color:var(--muted);text-decoration:none}
.footer-links a:hover{color:var(--text)}
@media(max-width:640px){nav{padding:0 20px}.hero,.features{padding:0 20px}.divider-row{padding:0 20px}.hero{margin-top:56px;margin-bottom:64px}h1{font-size:clamp(44px,12vw,72px)}footer{padding:24px 20px;flex-direction:column;gap:12px;text-align:center}}
</style>
</head>
<body>
<nav>
  <a href="/" class="brand">KECKER·PROJECTS</a>
  <div class="nav-right">${navRight}</div>
</nav>
<main>
  <div class="hero">
    <p class="eyebrow">Internal · Project Vault · MCP</p>
    <h1>Project context,<br><em>inside</em> Claude.</h1>
    <p class="sub">A private workspace connecting Claude to your project notes, tasks, and GitHub issues — built for the Kecker team.</p>
    ${heroCta}
  </div>
  <div class="divider-row"><span class="divider-text">What you get</span></div>
  <div class="features">
    <div class="features-grid">
      <div class="feature-card">
        <div class="feature-icon">✦</div>
        <h3>Project Notes</h3>
        <p>Per-project markdown notes stored in your vault. Claude can read and update them mid-conversation.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">◎</div>
        <h3>Task Tracking</h3>
        <p>Add, list, and complete tasks across all your projects. Priority levels and timestamps, always in sync.</p>
      </div>
      <div class="feature-card">
        <div class="feature-icon">⌥</div>
        <h3>GitHub Issues</h3>
        <p>Fetch open issues live from any KeckerCo repository, right inside the conversation.</p>
      </div>
    </div>
  </div>
</main>
<footer>
  <a href="/" class="footer-brand">KECKER·PROJECTS</a>
  <div class="footer-links">
    <a href="/.well-known/oauth-authorization-server">OAuth</a>
    <a href="/auth/login">Sign in</a>
  </div>
</footer>
</body>
</html>`;
}

// ── Auth pages ────────────────────────────────────────────────────────────────

const AUTH_ERRORS: Record<string, string> = {
  missing_fields: "Please enter your email and password.",
  invalid_email: "That doesn't look like a valid email.",
  weak_password: "Password must be at least 8 characters.",
  invalid_credentials: "Email or password incorrect.",
  email_taken: "An account with that email already exists. Sign in instead.",
  invite_required: "An invite link is required. Ask your admin for access.",
  invalid_invite: "This invite link is not valid.",
  invite_used: "This invite link has already been used.",
  invite_expired: "This invite link has expired. Ask your admin for a new one.",
  invite_email_mismatch: "This invite link is for a different email address.",
  rate_limited: "Too many attempts. Please try again later.",
};

function authPage(mode: "login" | "register", returnTo: string, error: string, invite = ""): string {
  const isLogin = mode === "login";
  const errMsg = AUTH_ERRORS[error] ?? "";
  const altRow = isLogin
    ? `<div class="alt">Need access? <span style="color:var(--text)">Ask your admin.</span></div>`
    : `<div class="alt">Already have an account? <a href="/auth/login?return_to=${encodeURIComponent(returnTo)}">Sign in</a></div>`;
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<title>${isLogin ? "Sign in" : "Create account"} — Kecker Projects</title>
${FONTS}
<style>
  ${CSS_VARS}
  *{box-sizing:border-box}html,body{margin:0;padding:0}
  body{font-family:var(--font);background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;min-height:100vh;display:grid;place-items:center;padding:24px}
  .brand-logo{display:flex;flex-direction:column;align-items:center;text-decoration:none;margin-bottom:32px}
  .brand-text{font-family:'Nunito',sans-serif;font-weight:700;font-size:28px;color:var(--text);line-height:0.9;letter-spacing:0.15em;margin-left:0.15em}
  .brand-sub{font-family:'Nunito',sans-serif;font-weight:700;font-size:13px;color:var(--muted);letter-spacing:0.2em;margin-top:4px}
  .brand-divider{width:80px;height:3px;background:var(--accent);margin:6px 0;border-radius:2px}
  .card{background:var(--surface);border:1px solid var(--surface-border);border-radius:16px;padding:32px;width:100%;max-width:400px}
  h1{font-size:22px;font-weight:600;margin:0 0 4px;letter-spacing:-0.02em}
  .sub{color:var(--muted);font-size:15px;margin:0 0 24px}
  label{display:block;font-size:13px;font-weight:500;color:var(--muted);margin-bottom:6px}
  input[type=email],input[type=password]{width:100%;background:var(--surface-hover);color:var(--text);border:1px solid var(--surface-border);border-radius:12px;padding:12px 16px;font:inherit;font-size:15px}
  input:focus{outline:none;border-color:var(--accent)}
  .field{margin-bottom:16px}
  button{width:100%;background:var(--accent);color:var(--bg);border:0;border-radius:12px;padding:14px 16px;font:inherit;font-size:15px;font-weight:600;cursor:pointer;margin-top:8px;box-shadow:0 4px 20px rgba(58,58,60,0.3);transition:transform .15s}
  button:hover{transform:scale(1.02)}
  .alt{text-align:center;margin-top:18px;font-size:14px;color:var(--muted)}
  .alt a{color:var(--accent);text-decoration:none;font-weight:500}
  .alt a:hover{text-decoration:underline}
  .error{background:var(--danger-soft);color:var(--danger);border:1px solid rgba(179,38,30,0.3);border-radius:12px;padding:12px 16px;font-size:13px;margin-bottom:16px;font-weight:500}
  .back{text-align:center;margin-top:16px;font-size:13px}
  .back a{color:var(--muted);text-decoration:none}
  .back a:hover{color:var(--text)}
</style>
</head><body>
<div>
  <a href="/" class="brand-logo">
    <div class="brand-text">KECKER</div>
    <div class="brand-divider"></div>
    <div class="brand-sub">PROJECTS</div>
  </a>
  <div class="card">
    <h1>${isLogin ? "Sign in" : "Create account"}</h1>
    <p class="sub">${isLogin ? "Welcome back." : "You've been invited to Kecker Projects."}</p>
    ${errMsg ? `<div class="error">${esc(errMsg)}</div>` : ""}
    <form method="POST" action="/auth/${mode}">
      <input type="hidden" name="return_to" value="${esc(returnTo)}"/>
      ${!isLogin && invite ? `<input type="hidden" name="invite_token" value="${esc(invite)}"/>` : ""}
      <div class="field"><label>Email</label><input type="email" name="email" required autocomplete="email" autofocus/></div>
      <div class="field"><label>Password</label><input type="password" name="password" required autocomplete="${isLogin ? "current-password" : "new-password"}" minlength="${isLogin ? 1 : 8}"/></div>
      <button type="submit">${isLogin ? "Sign in" : "Create account"}</button>
    </form>
    ${altRow}
  </div>
  <div class="back"><a href="/">← Home</a></div>
</div>
</body></html>`;
}

// ── OAuth consent page ────────────────────────────────────────────────────────

function consentPage(opts: { clientName: string; email: string; scope: string; params: Record<string, string> }): string {
  const hidden = Object.entries(opts.params)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}"/>`)
    .join("");
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Authorize — Kecker Projects</title>
${FONTS}
<style>
  ${CSS_VARS}
  *{box-sizing:border-box}html,body{margin:0;padding:0}
  body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;display:grid;place-items:center;padding:24px}
  .card{background:var(--surface);border:1px solid var(--surface-border);border-radius:16px;padding:32px;width:100%;max-width:400px}
  h1{font-size:20px;font-weight:600;margin:0 0 8px;letter-spacing:-0.02em}
  .meta{color:var(--muted);font-size:14px;margin:0 0 20px}
  .perms{background:var(--surface-hover);border:1px solid var(--surface-border);border-radius:12px;padding:14px 16px;margin:0 0 24px}
  .perms p{margin:0;font-size:14px;color:var(--muted);line-height:1.5}
  .perms strong{color:var(--text)}
  button{width:100%;background:var(--accent);color:var(--bg);border:0;border-radius:12px;padding:14px 16px;font:inherit;font-size:15px;font-weight:600;cursor:pointer;box-shadow:0 4px 20px rgba(58,58,60,0.3);transition:transform .15s}
  button:hover{transform:scale(1.02)}
  .deny{background:transparent;border:1px solid var(--surface-border);color:var(--muted);box-shadow:none;margin-top:10px}
  .deny:hover{transform:none;opacity:0.8}
</style>
</head><body>
<div class="card">
  <h1>Authorize ${esc(opts.clientName)}</h1>
  <p class="meta">Signed in as <strong>${esc(opts.email)}</strong></p>
  <div class="perms"><p><strong>${esc(opts.clientName)}</strong> is requesting access to your <strong>Kecker Projects</strong> vault and projects.</p></div>
  <form method="POST" action="/oauth/authorize">
    ${hidden}
    <button name="decision" value="approve">Allow access</button>
    <button name="decision" value="deny" class="deny">Deny</button>
  </form>
</div>
</body></html>`;
}

// ── Admin page ────────────────────────────────────────────────────────────────

async function adminPage(env: Env, session: SessionData, origin: string, newInviteToken?: string): Promise<string> {
  const now = Date.now();
  const [usersResult, invitesResult] = await Promise.all([
    env.DB.prepare("SELECT user_id, email, created_at FROM users ORDER BY created_at ASC")
      .all<{ user_id: string; email: string; created_at: number }>(),
    env.DB.prepare("SELECT token, email, expires_at, created_at FROM invites WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at DESC")
      .bind(now).all<{ token: string; email: string | null; expires_at: number; created_at: number }>(),
  ]);
  const users = usersResult.results ?? [];
  const pendingInvites = invitesResult.results ?? [];
  const newInviteUrl = newInviteToken ? `${origin}/auth/register?invite=${newInviteToken}` : null;

  const newInviteBanner = newInviteUrl ? `
  <div class="invite-banner">
    <p class="banner-label">Invite link ready — share it with your new member</p>
    <div class="connect-box">
      <code class="connect-url">${newInviteUrl}</code>
      <button class="copy-btn" onclick="navigator.clipboard.writeText('${newInviteUrl}').then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)})">Copy</button>
    </div>
    <p class="banner-hint">Expires in 7 days · Single use only</p>
  </div>` : "";

  const userRows = users.map(u => `
  <div class="row">
    <div class="row-main">
      <span class="row-email">${esc(u.email)}</span>
      <span class="row-meta">${fmtDate(u.created_at)}</span>
    </div>
    ${isAdmin(u.email, env)
      ? `<span class="badge">Admin</span>`
      : `<form method="POST" action="/admin/users/${esc(u.user_id)}/revoke" onsubmit="return confirm('Revoke access for ${esc(u.email)}?')">
          <button class="btn-revoke">Revoke</button>
        </form>`
    }
  </div>`).join("");

  const inviteRows = pendingInvites.length
    ? pendingInvites.map(inv => {
        const url = `${origin}/auth/register?invite=${inv.token}`;
        return `<div class="row">
    <div class="row-main">
      <span class="row-email">${inv.email ? esc(inv.email) : "<em>Open invite</em>"}</span>
      <span class="row-meta">Expires ${fmtDate(inv.expires_at)}</span>
    </div>
    <button class="copy-small" onclick="navigator.clipboard.writeText('${url}').then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy link',1500)})">Copy link</button>
  </div>`;
      }).join("")
    : `<p class="empty">No pending invites.</p>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin — Kecker Projects</title>
${FONTS}
<style>
${CSS_VARS}
*{box-sizing:border-box}html,body{margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column}
nav{display:flex;align-items:center;justify-content:space-between;padding:0 40px;height:64px;border-bottom:1px solid var(--surface-border)}
.brand{font-family:'Nunito',sans-serif;font-weight:700;font-size:15px;letter-spacing:0.2em;color:var(--text);text-decoration:none}
.nav-right{display:flex;align-items:center;gap:16px}
.nav-email{color:var(--muted);font-size:14px}
.nav-ghost{background:transparent;border:1px solid var(--surface-border);color:var(--muted);border-radius:8px;padding:7px 14px;font-size:13px;font-weight:500;text-decoration:none}
.nav-ghost:hover{color:var(--text)}
main{flex:1;max-width:720px;margin:0 auto;padding:48px 40px;width:100%}
.page-title{font-size:24px;font-weight:600;letter-spacing:-0.02em;margin:0 0 40px}
.invite-banner{background:var(--surface);border:1px solid var(--surface-border);border-radius:14px;padding:20px 24px;margin-bottom:40px}
.banner-label{font-size:12px;font-weight:600;color:var(--muted);margin:0 0 10px;text-transform:uppercase;letter-spacing:0.1em}
.banner-hint{font-size:13px;color:var(--muted);margin:10px 0 0}
.connect-box{display:flex;align-items:center;background:var(--surface-hover);border:1px solid var(--surface-border);border-radius:10px;padding:12px 14px;gap:12px}
.connect-url{font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-size:12px;color:var(--accent);flex:1;word-break:break-all}
.copy-btn{background:var(--accent);color:var(--bg);border:none;border-radius:8px;padding:7px 14px;font-family:var(--font);font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap}
.copy-btn:hover{opacity:0.85}
.section{margin-bottom:48px}
.section-title{font-size:11px;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:var(--muted);margin:0 0 16px;padding-bottom:12px;border-bottom:1px solid var(--surface-border)}
.invite-form{display:flex;gap:12px;align-items:flex-end}
.field-group{flex:1}
.field-group label{display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:6px}
.field-group input{width:100%;background:var(--surface);border:1px solid var(--surface-border);border-radius:10px;padding:10px 14px;font:inherit;font-size:14px;color:var(--text)}
.field-group input:focus{outline:none;border-color:var(--accent)}
.btn-generate{background:var(--accent);color:var(--bg);border:none;border-radius:10px;padding:10px 18px;font:inherit;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap}
.btn-generate:hover{opacity:0.88}
.row{display:flex;align-items:center;padding:13px 0;border-bottom:1px solid var(--surface-hover);gap:12px}
.row:last-child{border-bottom:none}
.row-main{flex:1;display:flex;align-items:baseline;gap:12px;min-width:0}
.row-email{font-size:14px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row-meta{font-size:12px;color:var(--muted);white-space:nowrap}
.badge{font-size:11px;font-weight:600;color:var(--muted);background:var(--surface-hover);border:1px solid var(--surface-border);border-radius:6px;padding:3px 8px;white-space:nowrap}
.btn-revoke{background:transparent;border:1px solid var(--surface-border);color:#B3261E;border-radius:8px;padding:6px 12px;font-size:13px;font-weight:500;cursor:pointer;font-family:var(--font);white-space:nowrap}
.btn-revoke:hover{background:#f9dedc;border-color:rgba(179,38,30,0.3)}
.copy-small{background:transparent;border:1px solid var(--surface-border);color:var(--muted);border-radius:8px;padding:6px 12px;font-size:13px;font-weight:500;cursor:pointer;font-family:var(--font);white-space:nowrap}
.copy-small:hover{color:var(--text)}
.empty{font-size:13px;color:var(--muted);margin:0;padding:12px 0}
@media(max-width:640px){nav,main{padding-left:20px;padding-right:20px}.invite-form{flex-direction:column}.btn-generate{width:100%}}
</style>
</head>
<body>
<nav>
  <a href="/" class="brand">KECKER·PROJECTS</a>
  <div class="nav-right">
    <span class="nav-email">${esc(session.email)}</span>
    <a href="/auth/logout" class="nav-ghost">Sign out</a>
  </div>
</nav>
<main>
  <h1 class="page-title">Admin</h1>
  ${newInviteBanner}
  <div class="section">
    <p class="section-title">Invite a member</p>
    <form method="POST" action="/admin/invite" class="invite-form">
      <div class="field-group">
        <label>Email address <span style="font-weight:400;color:var(--muted)">(optional — restricts link to this address)</span></label>
        <input type="email" name="email" placeholder="colleague@company.com" autocomplete="off"/>
      </div>
      <button type="submit" class="btn-generate">Generate invite link</button>
    </form>
  </div>
  <div class="section">
    <p class="section-title">Members (${users.length})</p>
    ${userRows || `<p class="empty">No members yet.</p>`}
  </div>
  <div class="section">
    <p class="section-title">Pending invites (${pendingInvites.length})</p>
    ${inviteRows}
  </div>
</main>
</body>
</html>`;
}

// ── MCP server (tools) ────────────────────────────────────────────────────────

function buildMcpServer(env: Env): McpServer {
  const server = new McpServer({ name: "kecker-mcp", version: "1.0.0" });

  server.tool("list_projects", "List all KeckerCo projects tracked in this vault", {}, async () => {
    const rows = PROJECTS.map(p => `• **${p.id}** — ${p.description || "(no description)"}\n  https://github.com/${env.GITHUB_ORG}/${p.repo}`);
    return { content: [{ type: "text", text: rows.join("\n\n") }] };
  });

  server.tool(
    "get_project",
    "Get notes and tasks for a KeckerCo project",
    { project: z.string().describe("Project ID, e.g. architekt") },
    async ({ project }) => {
      const p = PROJECTS.find(x => x.id === project);
      if (!p) return { content: [{ type: "text", text: `Unknown project: ${project}. Use list_projects to see valid IDs.` }] };
      const [notes, tasks] = await Promise.all([
        env.VAULT.get(`notes:${project}`),
        env.VAULT.get(`tasks:${project}`),
      ]);
      const text = [
        `# ${p.id}`,
        `**Repo:** https://github.com/${env.GITHUB_ORG}/${p.repo}`,
        `**Description:** ${p.description || "—"}`,
        "",
        "## Notes",
        notes ?? "(no notes yet)",
        "",
        "## Tasks",
        tasks ?? "(no tasks yet)",
      ].join("\n");
      return { content: [{ type: "text", text }] };
    }
  );

  server.tool(
    "update_notes",
    "Save markdown notes for a KeckerCo project",
    { project: z.string().describe("Project ID"), notes: z.string().describe("Markdown notes content") },
    async ({ project, notes }) => {
      if (!PROJECTS.find(x => x.id === project)) return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
      await env.VAULT.put(`notes:${project}`, notes);
      return { content: [{ type: "text", text: `Notes updated for ${project}.` }] };
    }
  );

  server.tool(
    "create_task",
    "Add a task to a KeckerCo project",
    {
      project: z.string().describe("Project ID"),
      task: z.string().describe("Task description"),
      priority: z.enum(["low", "medium", "high"]).optional().describe("Priority (default: medium)"),
    },
    async ({ project, task, priority = "medium" }) => {
      if (!PROJECTS.find(x => x.id === project)) return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
      const existing = (await env.VAULT.get(`tasks:${project}`)) ?? "";
      const date = new Date().toISOString().split("T")[0];
      const line = `- [ ] [${priority}] ${task} _(${date})_`;
      await env.VAULT.put(`tasks:${project}`, existing ? `${existing}\n${line}` : line);
      return { content: [{ type: "text", text: `Task added to ${project}.` }] };
    }
  );

  server.tool(
    "list_tasks",
    "List open tasks for a project, or all projects",
    { project: z.string().optional().describe("Project ID; omit for all") },
    async ({ project }) => {
      const targets = project ? PROJECTS.filter(x => x.id === project) : PROJECTS;
      const parts: string[] = [];
      for (const p of targets) {
        const tasks = await env.VAULT.get(`tasks:${p.id}`);
        if (tasks) parts.push(`## ${p.id}\n${tasks}`);
      }
      return { content: [{ type: "text", text: parts.length ? parts.join("\n\n") : "No tasks found." }] };
    }
  );

  server.tool(
    "complete_task",
    "Mark a task as done by matching text",
    {
      project: z.string().describe("Project ID"),
      task_text: z.string().describe("Partial text of the task to mark complete"),
    },
    async ({ project, task_text }) => {
      const existing = await env.VAULT.get(`tasks:${project}`);
      if (!existing) return { content: [{ type: "text", text: `No tasks for ${project}.` }] };
      const updated = existing.split("\n")
        .map(l => (l.includes(task_text) && l.startsWith("- [ ]") ? l.replace("- [ ]", "- [x]") : l))
        .join("\n");
      await env.VAULT.put(`tasks:${project}`, updated);
      return { content: [{ type: "text", text: `Marked complete in ${project}: "${task_text}"` }] };
    }
  );

  server.tool(
    "get_github_issues",
    "Fetch open GitHub issues for a KeckerCo project",
    {
      project: z.string().describe("Project ID"),
      limit: z.number().int().min(1).max(50).optional().describe("Max issues (default 10)"),
    },
    async ({ project, limit = 10 }) => {
      const p = PROJECTS.find(x => x.id === project);
      if (!p) return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
      const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json", "User-Agent": "kecker-mcp/1.0" };
      if (env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${env.GITHUB_TOKEN}`;
      try {
        const res = await fetch(`https://api.github.com/repos/${env.GITHUB_ORG}/${p.repo}/issues?state=open&per_page=${limit}`, { headers });
        if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
        const issues = await res.json() as Array<{ number: number; title: string; html_url: string }>;
        if (!issues.length) return { content: [{ type: "text", text: `No open issues in ${project}.` }] };
        return { content: [{ type: "text", text: issues.map(i => `#${i.number} ${i.title}\n  ${i.html_url}`).join("\n\n") }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${(e as Error).message}` }] };
      }
    }
  );

  return server;
}

// ── OAuth helpers ─────────────────────────────────────────────────────────────

function oauthMeta(origin: string) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    scopes_supported: SUPPORTED_SCOPES,
  };
}

function protectedResourceMeta(origin: string) {
  return {
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    scopes_supported: SUPPORTED_SCOPES,
  };
}

async function issueTokens(env: Env, opts: { client_id: string; user_id: string; scope: string | null; resource: string | null }) {
  const accessToken  = randomToken("at");
  const refreshToken = randomToken("rt");
  const accessHash   = await hashSecret(accessToken,  env.MCP_TOKEN_PEPPER);
  const refreshHash  = await hashSecret(refreshToken, env.MCP_TOKEN_PEPPER);
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO oauth_access_tokens (token_hash,client_id,user_id,scope,resource,expires_at,created_at) VALUES (?,?,?,?,?,?,?)")
      .bind(accessHash, opts.client_id, opts.user_id, opts.scope, opts.resource, now + ACCESS_TOKEN_TTL_MS, now),
    env.DB.prepare("INSERT INTO oauth_refresh_tokens (token_hash,client_id,user_id,scope,resource,expires_at,created_at) VALUES (?,?,?,?,?,?,?)")
      .bind(refreshHash, opts.client_id, opts.user_id, opts.scope, opts.resource, now + REFRESH_TOKEN_TTL_MS, now),
  ]);
  return { access_token: accessToken, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_MS / 1000, refresh_token: refreshToken, scope: opts.scope ?? "mcp" };
}

// ── Main fetch handler ────────────────────────────────────────────────────────

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url    = new URL(req.url);
    const origin = url.origin;
    const path   = url.pathname;
    const method = req.method;

    if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

    // ── RFC metadata ──────────────────────────────────────────────────────────
    if (path === "/.well-known/oauth-authorization-server") return json(oauthMeta(origin));
    if (path === "/.well-known/oauth-protected-resource")   return json(protectedResourceMeta(origin));

    // ── Landing page ──────────────────────────────────────────────────────────
    if (path === "/" && method === "GET") {
      const session = await readSession(req, env);
      return html(200, landingPage(session, origin, env));
    }

    // ── Auth pages ────────────────────────────────────────────────────────────
    if (path === "/auth/register" && method === "GET") {
      const invite = url.searchParams.get("invite") ?? "";
      if (invite) {
        const inv = await env.DB.prepare("SELECT used_at, expires_at FROM invites WHERE token = ?")
          .bind(invite).first<{ used_at: number | null; expires_at: number }>();
        if (!inv) return html(400, authPage("register", "/", "invalid_invite"));
        if (inv.used_at !== null) return html(400, authPage("register", "/", "invite_used"));
        if (inv.expires_at < Date.now()) return html(400, authPage("register", "/", "invite_expired"));
      }
      return html(200, authPage("register", url.searchParams.get("return_to") ?? "/", url.searchParams.get("error") ?? "", invite));
    }
    if (path === "/auth/register" && method === "POST") {
      const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
      const regLimit = await d1RateLimit(env.DB, `register:ip:${ip}`, 5, 60 * 60_000);
      if (!regLimit.allowed) {
        return html(429, authPage("register", "/", "rate_limited"), new Headers({ "Retry-After": String(regLimit.retryAfterSec) }));
      }
      const form = await req.formData();
      const email       = String(form.get("email") ?? "").trim().toLowerCase();
      const password    = String(form.get("password") ?? "");
      const returnTo    = String(form.get("return_to") ?? "/");
      const inviteToken = String(form.get("invite_token") ?? "").trim();
      const safeReturn  = returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";
      if (!email || !password) return html(400, authPage("register", safeReturn, "missing_fields", inviteToken));
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return html(400, authPage("register", safeReturn, "invalid_email", inviteToken));
      if (password.length < 8) return html(400, authPage("register", safeReturn, "weak_password", inviteToken));

      let inviteRow: { token: string; email: string | null; used_at: number | null; expires_at: number } | null = null;
      if (!isAdmin(email, env)) {
        if (!inviteToken) return html(400, authPage("register", safeReturn, "invite_required", ""));
        inviteRow = await env.DB.prepare("SELECT token, email, used_at, expires_at FROM invites WHERE token = ?")
          .bind(inviteToken).first<{ token: string; email: string | null; used_at: number | null; expires_at: number }>();
        if (!inviteRow) return html(400, authPage("register", safeReturn, "invalid_invite", ""));
        if (inviteRow.used_at !== null) return html(400, authPage("register", safeReturn, "invite_used", ""));
        if (inviteRow.expires_at < Date.now()) return html(400, authPage("register", safeReturn, "invite_expired", ""));
        if (inviteRow.email && inviteRow.email !== email) return html(400, authPage("register", safeReturn, "invite_email_mismatch", inviteToken));
      }

      const existing = await env.DB.prepare("SELECT user_id FROM users WHERE email = ?").bind(email).first<{ user_id: string }>();
      if (existing) return html(409, authPage("register", safeReturn, "email_taken", inviteToken));
      const userId = `usr_${crypto.randomUUID().replace(/-/g,"")}`;
      const hash   = await hashPassword(password);
      const now    = Date.now();
      await env.DB.prepare("INSERT INTO users (user_id,email,password_hash,created_at) VALUES (?,?,?,?)").bind(userId, email, hash, now).run();
      if (inviteRow) {
        await env.DB.prepare("UPDATE invites SET used_at = ?, used_by_email = ? WHERE token = ?").bind(now, email, inviteToken).run();
      }
      const headers = await issueSession(req, env, { user_id: userId, email });
      headers.set("Location", safeReturn);
      return new Response(null, { status: 303, headers });
    }

    if (path === "/auth/login" && method === "GET") {
      return html(200, authPage("login", url.searchParams.get("return_to") ?? "/", url.searchParams.get("error") ?? ""));
    }
    if (path === "/auth/login" && method === "POST") {
      const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
      const ipLimit = await d1RateLimit(env.DB, `login:ip:${ip}`, 20, 15 * 60_000);
      if (!ipLimit.allowed) {
        return html(429, authPage("login", "/", "rate_limited"), new Headers({ "Retry-After": String(ipLimit.retryAfterSec) }));
      }
      const form = await req.formData();
      const email    = String(form.get("email") ?? "").trim().toLowerCase();
      const password = String(form.get("password") ?? "");
      const returnTo = String(form.get("return_to") ?? "/");
      const safeReturn = returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";
      if (!email || !password) return html(400, authPage("login", safeReturn, "missing_fields"));
      // Per-email rate limit after form parsing (avoids leaking enumerable emails via timing)
      const emailLimit = await d1RateLimit(env.DB, `login:email:${email}`, 10, 15 * 60_000);
      if (!emailLimit.allowed) return html(429, authPage("login", safeReturn, "rate_limited"));
      const row = await env.DB.prepare("SELECT user_id, password_hash FROM users WHERE email = ?").bind(email).first<{ user_id: string; password_hash: string }>();
      const check = row ? await verifyPassword(password, row.password_hash) : { valid: false, needsRehash: false };
      if (!row || !check.valid) return html(401, authPage("login", safeReturn, "invalid_credentials"));
      if (check.needsRehash) {
        const newHash = await hashPassword(password);
        await env.DB.prepare("UPDATE users SET password_hash = ? WHERE user_id = ?").bind(newHash, row.user_id).run();
      }
      // Invalidate old sessions before issuing a new one
      await env.DB.prepare("DELETE FROM web_sessions WHERE user_id = ?").bind(row.user_id).run();
      const headers = await issueSession(req, env, { user_id: row.user_id, email });
      headers.set("Location", safeReturn);
      return new Response(null, { status: 303, headers });
    }

    if (path === "/auth/logout") {
      return redirect("/", clearSessionHeader());
    }

    // ── OAuth: client registration ────────────────────────────────────────────
    if (path === "/oauth/register" && method === "POST") {
      const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
      const regLimit = await d1RateLimit(env.DB, `oauth_reg:${ip}`, 10, 60 * 60_000);
      if (!regLimit.allowed) return json({ error: "rate_limit_exceeded", error_description: "Too many registration requests" }, 429);
      let body: any;
      try { body = await req.json(); } catch { return json({ error: "invalid_request" }, 400); }
      const redirectUris: unknown = body.redirect_uris;
      if (!Array.isArray(redirectUris) || redirectUris.length === 0) return json({ error: "invalid_redirect_uri" }, 400);
      for (const u of redirectUris) if (typeof u !== "string" || !isValidRedirectUri(u)) return json({ error: "invalid_redirect_uri" }, 400);
      const tokenAuthMethod: string = typeof body.token_endpoint_auth_method === "string" ? body.token_endpoint_auth_method : "client_secret_post";
      if (!["client_secret_post", "client_secret_basic", "none"].includes(tokenAuthMethod)) return json({ error: "invalid_client_metadata" }, 400);
      const clientId     = randomClientId();
      const clientSecret = tokenAuthMethod === "none" ? "" : randomToken("cs");
      const secretHash   = clientSecret ? await hashSecret(clientSecret, env.MCP_TOKEN_PEPPER) : "";
      const clientName   = typeof body.client_name === "string" ? body.client_name : null;
      const scope        = typeof body.scope === "string" ? body.scope : "mcp";
      const grantTypes   = Array.isArray(body.grant_types)   && body.grant_types.length   > 0 ? body.grant_types   : ["authorization_code", "refresh_token"];
      const responseTypes= Array.isArray(body.response_types)&& body.response_types.length> 0 ? body.response_types: ["code"];
      await env.DB.prepare("INSERT INTO oauth_clients (client_id,client_secret_hash,client_name,redirect_uris_json,token_endpoint_auth_method,grant_types_json,response_types_json,scope,created_at) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(clientId, secretHash, clientName, JSON.stringify(redirectUris), tokenAuthMethod, JSON.stringify(grantTypes), JSON.stringify(responseTypes), scope, Date.now()).run();
      const resp: Record<string, unknown> = { client_id: clientId, client_id_issued_at: Math.floor(Date.now()/1000), redirect_uris: redirectUris, grant_types: grantTypes, response_types: responseTypes, token_endpoint_auth_method: tokenAuthMethod, scope };
      if (clientSecret) resp.client_secret = clientSecret;
      if (clientName)   resp.client_name   = clientName;
      return json(resp, 201);
    }

    // ── OAuth: authorize ──────────────────────────────────────────────────────
    if (path === "/oauth/authorize") {
      const params = method === "GET" ? url.searchParams : new URLSearchParams(await req.text());
      const clientId            = params.get("client_id") ?? "";
      const redirectUri         = params.get("redirect_uri") ?? "";
      const responseType        = params.get("response_type") ?? "";
      const codeChallenge       = params.get("code_challenge") ?? "";
      const codeChallengeMethod = params.get("code_challenge_method") ?? "";
      const state               = params.get("state") ?? "";
      const scope               = params.get("scope") ?? "mcp";
      const resource            = params.get("resource") ?? "";
      const decision            = params.get("decision") ?? "";

      if (!clientId || !redirectUri) return json({ error: "invalid_request" }, 400);
      const client = await env.DB.prepare("SELECT client_id, client_name, redirect_uris_json FROM oauth_clients WHERE client_id = ?").bind(clientId).first<{ client_id: string; client_name: string | null; redirect_uris_json: string }>();
      if (!client) return json({ error: "invalid_client" }, 400);
      const registered = JSON.parse(client.redirect_uris_json) as string[];
      if (!registered.includes(redirectUri)) return json({ error: "invalid_redirect_uri" }, 400);
      if (responseType !== "code") { const u = new URL(redirectUri); u.searchParams.set("error", "unsupported_response_type"); if (state) u.searchParams.set("state", state); return redirect(u.toString()); }
      if (!codeChallenge || codeChallengeMethod !== "S256") { const u = new URL(redirectUri); u.searchParams.set("error", "invalid_request"); u.searchParams.set("error_description", "PKCE S256 required"); if (state) u.searchParams.set("state", state); return redirect(u.toString()); }

      const session = await readSession(req, env);
      if (!session) {
        if (method === "GET") return redirect(`/auth/login?return_to=${encodeURIComponent(path + url.search)}`);
        return json({ error: "login_required" }, 401);
      }

      if (method === "GET") {
        return html(200, consentPage({
          clientName: client.client_name || clientId,
          email: session.email,
          scope,
          params: { client_id: clientId, redirect_uri: redirectUri, response_type: responseType, code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod, state, scope, resource },
        }));
      }

      if (decision !== "approve") { const u = new URL(redirectUri); u.searchParams.set("error", "access_denied"); if (state) u.searchParams.set("state", state); return redirect(u.toString()); }

      const code     = randomToken("ac");
      const codeHash = await hashSecret(code, env.MCP_TOKEN_PEPPER);
      const now      = Date.now();
      await env.DB.prepare("INSERT INTO oauth_authorization_codes (code_hash,client_id,user_id,redirect_uri,code_challenge,code_challenge_method,scope,resource,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
        .bind(codeHash, clientId, session.user_id, redirectUri, codeChallenge, codeChallengeMethod, scope, resource || null, now + AUTH_CODE_TTL_MS, now).run();
      const target = new URL(redirectUri);
      target.searchParams.set("code", code);
      if (state) target.searchParams.set("state", state);
      return redirect(target.toString());
    }

    // ── OAuth: token endpoint ─────────────────────────────────────────────────
    if (path === "/oauth/token" && method === "POST") {
      const form = await req.formData();
      const grantType = String(form.get("grant_type") ?? "");

      if (grantType === "authorization_code") {
        const code        = String(form.get("code") ?? "");
        const redirectUri = String(form.get("redirect_uri") ?? "");
        const verifier    = String(form.get("code_verifier") ?? "");
        const clientId    = String(form.get("client_id") ?? "");
        if (!code || !redirectUri || !verifier || !clientId) return json({ error: "invalid_request" }, 400);
        const codeHash = await hashSecret(code, env.MCP_TOKEN_PEPPER);
        const row = await env.DB.prepare("SELECT client_id, user_id, redirect_uri, code_challenge, code_challenge_method, scope, resource, expires_at, consumed_at FROM oauth_authorization_codes WHERE code_hash = ?")
          .bind(codeHash).first<{ client_id: string; user_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: string; scope: string | null; resource: string | null; expires_at: number; consumed_at: number | null }>();
        if (!row) return json({ error: "invalid_grant" }, 400);
        if (row.consumed_at !== null) return json({ error: "invalid_grant", error_description: "code already used" }, 400);
        if (row.expires_at < Date.now()) return json({ error: "invalid_grant", error_description: "code expired" }, 400);
        if (row.client_id !== clientId) return json({ error: "invalid_grant" }, 400);
        if (row.redirect_uri !== redirectUri) return json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, 400);
        if (!(await verifyPkce(verifier, row.code_challenge, row.code_challenge_method))) return json({ error: "invalid_grant", error_description: "code_verifier mismatch" }, 400);
        await env.DB.prepare("UPDATE oauth_authorization_codes SET consumed_at = ? WHERE code_hash = ?").bind(Date.now(), codeHash).run();
        return json(await issueTokens(env, { client_id: clientId, user_id: row.user_id, scope: row.scope, resource: row.resource }));
      }

      if (grantType === "refresh_token") {
        const refreshRaw = String(form.get("refresh_token") ?? "");
        const clientId   = String(form.get("client_id") ?? "");
        if (!refreshRaw) return json({ error: "invalid_request" }, 400);
        const refreshHash = await hashSecret(refreshRaw, env.MCP_TOKEN_PEPPER);
        const row = await env.DB.prepare("SELECT client_id, user_id, scope, resource, expires_at, revoked_at, rotated_to FROM oauth_refresh_tokens WHERE token_hash = ?")
          .bind(refreshHash).first<{ client_id: string; user_id: string; scope: string | null; resource: string | null; expires_at: number | null; revoked_at: number | null; rotated_to: string | null }>();
        if (!row || row.revoked_at !== null || row.rotated_to) return json({ error: "invalid_grant" }, 400);
        if (row.expires_at && row.expires_at < Date.now()) return json({ error: "invalid_grant", error_description: "expired" }, 400);
        if (clientId && row.client_id !== clientId) return json({ error: "invalid_grant" }, 400);
        const tokens = await issueTokens(env, { client_id: row.client_id, user_id: row.user_id, scope: row.scope, resource: row.resource });
        const newRefreshHash = await hashSecret(tokens.refresh_token, env.MCP_TOKEN_PEPPER);
        await env.DB.prepare("UPDATE oauth_refresh_tokens SET rotated_to = ?, revoked_at = ? WHERE token_hash = ? AND rotated_to IS NULL").bind(newRefreshHash, Date.now(), refreshHash).run();
        return json(tokens);
      }

      return json({ error: "unsupported_grant_type" }, 400);
    }

    // ── MCP endpoint ──────────────────────────────────────────────────────────
    if (path === "/" || path.startsWith("/mcp") || req.headers.has("Authorization")) {
      // Handle both /mcp/* and bare / calls from MCP clients
      const isMcpPath = path === "/" || path.startsWith("/mcp");
      if (isMcpPath && req.headers.has("Authorization")) {
        const token = req.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
        const info  = await authenticateAccessToken(env, token);
        if (!info) {
          return new Response(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null }), {
            status: 401,
            headers: {
              "Content-Type": "application/json",
              "WWW-Authenticate": `Bearer realm="mcp", resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
              ...CORS_HEADERS,
            },
          });
        }
        return createMcpHandler(buildMcpServer(env))(req, env, ctx);
      }
      // MCP path without auth — return 401 with WWW-Authenticate
      if (isMcpPath) {
        return new Response(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null }), {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": `Bearer realm="mcp", resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
            ...CORS_HEADERS,
          },
        });
      }
    }

    // ── Admin routes ──────────────────────────────────────────────────────────
    if (path === "/admin" && method === "GET") {
      const session = await readSession(req, env);
      if (!session || !isAdmin(session.email, env)) return redirect("/auth/login?return_to=/admin");
      const newInviteToken = url.searchParams.get("new_invite") ?? undefined;
      return html(200, await adminPage(env, session, origin, newInviteToken));
    }

    if (path === "/admin/invite" && method === "POST") {
      const session = await readSession(req, env);
      if (!session || !isAdmin(session.email, env)) return json({ error: "forbidden" }, 403);
      const form     = await req.formData();
      const email    = String(form.get("email") ?? "").trim().toLowerCase() || null;
      const token    = randomToken("inv");
      const now      = Date.now();
      await env.DB.prepare(
        "INSERT INTO invites (token, created_by_email, email, expires_at, created_at) VALUES (?,?,?,?,?)"
      ).bind(token, session.email, email, now + INVITE_TTL_MS, now).run();
      return redirect(`/admin?new_invite=${token}`);
    }

    if (path.startsWith("/admin/users/") && path.endsWith("/revoke") && method === "POST") {
      const session = await readSession(req, env);
      if (!session || !isAdmin(session.email, env)) return json({ error: "forbidden" }, 403);
      const parts  = path.split("/");
      const userId = parts[3];
      if (!userId) return redirect("/admin");
      const target = await env.DB.prepare("SELECT email FROM users WHERE user_id = ?").bind(userId).first<{ email: string }>();
      if (target && !isAdmin(target.email, env)) {
        await env.DB.batch([
          env.DB.prepare("DELETE FROM web_sessions WHERE user_id = ?").bind(userId),
          env.DB.prepare("UPDATE oauth_access_tokens SET revoked_at = ? WHERE user_id = ?").bind(Date.now(), userId),
          env.DB.prepare("UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE user_id = ?").bind(Date.now(), userId),
          env.DB.prepare("DELETE FROM users WHERE user_id = ?").bind(userId),
        ]);
      }
      return redirect("/admin");
    }

    return new Response("Not found", { status: 404 });
  },
};
