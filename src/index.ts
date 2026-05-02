import { createMcpHandler } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export interface Env {
  VAULT: KVNamespace;
  GITHUB_ORG: string;
  VAULT_REPO: string;
  GITHUB_TOKEN?: string;
  KECKER_MCP_TOKEN?: string;
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
    {
      project: z.string().describe("Project ID"),
      notes: z.string().describe("Markdown notes content to save"),
    },
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
    { project: z.string().optional().describe("Project ID; omit for all projects") },
    async ({ project }) => {
      const targets = project
        ? PROJECTS.filter((x) => x.id === project)
        : PROJECTS;
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
      limit: z.number().int().min(1).max(50).optional().describe("Max issues to return (default 10)"),
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
        const text = issues.map((i) => `#${i.number} ${i.title}\n  ${i.html_url}`).join("\n\n");
        return { content: [{ type: "text", text }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${(e as Error).message}` }] };
      }
    }
  );

  return server;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const token = env.KECKER_MCP_TOKEN;
    if (token) {
      const auth = req.headers.get("Authorization") ?? "";
      if (auth !== `Bearer ${token}`) {
        return new Response("Unauthorized", { status: 401 });
      }
    }
    const handler = createMcpHandler(buildMcpServer(env));
    return handler(req, env, ctx);
  },
};
