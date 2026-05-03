import { createMcpHandler } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export interface Env {
  VAULT: KVNamespace;
  GITHUB_ORG: string;
  VAULT_REPO: string;
  GITHUB_TOKEN?: string;
  KECKER_MCP_TOKEN?: string;
  OAUTH_CLIENT_ID?: string;
  OAUTH_CLIENT_SECRET?: string;
}

const PROJECTS = [
  { id: "architekt", repo: "architekt", description: "Kotlin multiplatform composable architecture" },
  { id: "design", repo: "design", description: "KeckerCo design assets and system" },
  { id: "kecker-docs-cloudflare", repo: "kecker-docs-cloudflare", description: "Kecker docs site on Cloudflare Pages" },
  { id: "Klojure", repo: "Klojure", description: "A Clojure wrapper for KMP" },
  { id: "particular-baptists", repo: "particular-baptists", description: "Historical Particular Baptist Library — IRBS project" },
  { id: "shrink", repo: "shrink", description: "" },
  { id: "true-confessions-compose-multiplatform", repo: "true-confessions-compose-multiplatform", description: "True Confessions Compose Multiplatform app" },
];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

function randomToken(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function validateBearer(req: Request, env: Env): Promise<boolean> {
  const auth = req.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  // static token
  if (env.KECKER_MCP_TOKEN && token === env.KECKER_MCP_TOKEN) return true;
  // oauth-issued access token stored in KV
  const stored = await env.VAULT.get(`oauth:access:${token}`);
  return stored !== null;
}

function buildMcpServer(env: Env): McpServer {
  const server = new McpServer({ name: "kecker-mcp", version: "1.0.0" });

  server.tool("list_projects", "List all KeckerCo projects tracked in this vault", {}, async () => {
    const rows = PROJECTS.map(
      (p) => `• **${p.id}** — ${p.description || "(no description)"}\n  https://github.com/${env.GITHUB_ORG}/${p.repo}`
    );
    return { content: [{ type: "text", text: rows.join("\n\n") }] };
  });

  server.tool(
    "get_project",
    "Get notes and tasks for a KeckerCo project",
    { project: z.string().describe("Project ID, e.g. architekt") },
    async ({ project }) => {
      const p = PROJECTS.find((x) => x.id === project);
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
      if (!PROJECTS.find((x) => x.id === project))
        return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
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
      if (!PROJECTS.find((x) => x.id === project))
        return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
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
      const targets = project ? PROJECTS.filter((x) => x.id === project) : PROJECTS;
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
      const updated = existing
        .split("\n")
        .map((l) => (l.includes(task_text) && l.startsWith("- [ ]") ? l.replace("- [ ]", "- [x]") : l))
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
      const p = PROJECTS.find((x) => x.id === project);
      if (!p) return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
      const headers: Record<string, string> = {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "kecker-mcp/1.0",
      };
      if (env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${env.GITHUB_TOKEN}`;
      try {
        const res = await fetch(
          `https://api.github.com/repos/${env.GITHUB_ORG}/${p.repo}/issues?state=open&per_page=${limit}`,
          { headers }
        );
        if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
        const issues = (await res.json()) as Array<{ number: number; title: string; html_url: string }>;
        if (!issues.length) return { content: [{ type: "text", text: `No open issues in ${project}.` }] };
        return { content: [{ type: "text", text: issues.map((i) => `#${i.number} ${i.title}\n  ${i.html_url}`).join("\n\n") }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${(e as Error).message}` }] };
      }
    }
  );

  return server;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const origin = url.origin;

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    // ── OAuth 2.0 protected resource metadata (RFC 9728) ──────────────────
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json({
        resource: origin,
        authorization_servers: [`${origin}`],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp"],
      });
    }

    // ── OAuth 2.0 authorization server metadata (RFC 8414) ────────────────
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return json({
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
        grant_types_supported: ["authorization_code", "client_credentials"],
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["mcp"],
      });
    }

    // ── Authorization endpoint (authorization code flow) ──────────────────
    if (url.pathname === "/authorize") {
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state") ?? "";
      const codeChallenge = url.searchParams.get("code_challenge");

      if (!clientId || clientId !== env.OAUTH_CLIENT_ID) {
        return json({ error: "invalid_client" }, 400);
      }
      if (!redirectUri) {
        return json({ error: "invalid_request", error_description: "redirect_uri required" }, 400);
      }

      // Auto-approve: generate authorization code
      const code = randomToken(24);
      await env.VAULT.put(
        `oauth:code:${code}`,
        JSON.stringify({ clientId, redirectUri, codeChallenge }),
        { expirationTtl: 300 } // 5 minutes
      );

      const redirect = new URL(redirectUri);
      redirect.searchParams.set("code", code);
      if (state) redirect.searchParams.set("state", state);
      return Response.redirect(redirect.toString(), 302);
    }

    // ── Token endpoint ─────────────────────────────────────────────────────
    if (url.pathname === "/token" && req.method === "POST") {
      let params: Record<string, string> = {};

      const ct = req.headers.get("Content-Type") ?? "";
      if (ct.includes("application/x-www-form-urlencoded")) {
        const text = await req.text();
        for (const [k, v] of new URLSearchParams(text)) params[k] = v;
      } else {
        params = (await req.json()) as Record<string, string>;
      }

      // Support HTTP Basic auth for client credentials
      const basic = req.headers.get("Authorization");
      if (basic?.startsWith("Basic ")) {
        const [id, secret] = atob(basic.slice(6)).split(":", 2);
        params.client_id ??= id;
        params.client_secret ??= secret;
      }

      const { grant_type, client_id, client_secret, code, code_verifier, redirect_uri } = params;

      // Validate client identity for all flows
      if (client_id !== env.OAUTH_CLIENT_ID || client_secret !== env.OAUTH_CLIENT_SECRET) {
        return json({ error: "invalid_client" }, 401);
      }

      if (grant_type === "authorization_code") {
        if (!code) return json({ error: "invalid_request", error_description: "code required" }, 400);

        const stored = await env.VAULT.get(`oauth:code:${code}`);
        if (!stored) return json({ error: "invalid_grant" }, 400);

        const { redirectUri, codeChallenge } = JSON.parse(stored) as {
          clientId: string;
          redirectUri: string;
          codeChallenge?: string;
        };

        if (redirect_uri && redirect_uri !== redirectUri) {
          return json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, 400);
        }

        // Verify PKCE if used
        if (codeChallenge && code_verifier) {
          const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code_verifier));
          const b64 = btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
          if (b64 !== codeChallenge) {
            return json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
          }
        }

        // Consume the code
        await env.VAULT.delete(`oauth:code:${code}`);

        const accessToken = randomToken(32);
        await env.VAULT.put(`oauth:access:${accessToken}`, "1", { expirationTtl: 3600 * 24 * 30 });

        return json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600 * 24 * 30, scope: "mcp" });

      } else if (grant_type === "client_credentials") {
        const accessToken = randomToken(32);
        await env.VAULT.put(`oauth:access:${accessToken}`, "1", { expirationTtl: 3600 * 24 * 30 });
        return json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600 * 24 * 30, scope: "mcp" });

      } else {
        return json({ error: "unsupported_grant_type" }, 400);
      }
    }

    // ── All other routes require auth ──────────────────────────────────────
    const authed = await validateBearer(req, env);
    if (!authed) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": `Bearer realm="${origin}", resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
          ...CORS,
        },
      });
    }

    const handler = createMcpHandler(buildMcpServer(env));
    return handler(req, env, ctx);
  },
};
