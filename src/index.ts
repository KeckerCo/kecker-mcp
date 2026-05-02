import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export interface Env {
  VAULT: KVNamespace;
  GITHUB_ORG: string;
  VAULT_REPO: string;
  GITHUB_TOKEN?: string;
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

async function githubRequest(path: string, env: Env, options: RequestInit = {}) {
  const headers: Record<string, string> = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "kecker-mcp/1.0",
  };
  if (env.GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${env.GITHUB_TOKEN}`;
  }
  const res = await fetch(`https://api.github.com${path}`, { ...options, headers: { ...headers, ...(options.headers as Record<string, string> || {}) } });
  if (!res.ok) throw new Error(`GitHub API ${path}: ${res.status} ${await res.text()}`);
  return res.json() as Promise<unknown>;
}

export class KeckerMCP extends McpAgent<Env> {
  server = new McpServer({ name: "kecker-mcp", version: "1.0.0" });

  async init() {
    // list_projects — enumerate all KeckerCo projects
    this.server.tool(
      "list_projects",
      "List all KeckerCo GitHub projects tracked in this vault",
      {},
      async () => {
        const rows = PROJECTS.map(
          (p) => `• **${p.id}** — ${p.description || "(no description)"}\n  Repo: https://github.com/${this.env.GITHUB_ORG}/${p.repo}`
        );
        return { content: [{ type: "text", text: rows.join("\n\n") }] };
      }
    );

    // get_project — metadata + latest notes from KV
    this.server.tool(
      "get_project",
      "Get notes and metadata for a specific KeckerCo project",
      { project: z.string().describe("Project ID, e.g. architekt") },
      async ({ project }) => {
        const p = PROJECTS.find((x) => x.id === project);
        if (!p) return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
        const notes = await this.env.VAULT.get(`notes:${project}`) ?? "(no notes yet)";
        const tasks = await this.env.VAULT.get(`tasks:${project}`) ?? "(no tasks yet)";
        const text = [
          `# ${p.id}`,
          `**Repo:** https://github.com/${this.env.GITHUB_ORG}/${p.repo}`,
          `**Description:** ${p.description || "—"}`,
          "",
          "## Notes",
          notes,
          "",
          "## Tasks",
          tasks,
        ].join("\n");
        return { content: [{ type: "text", text }] };
      }
    );

    // update_notes — write notes for a project into KV
    this.server.tool(
      "update_notes",
      "Update the notes for a KeckerCo project",
      {
        project: z.string().describe("Project ID"),
        notes: z.string().describe("Markdown notes content to save"),
      },
      async ({ project, notes }) => {
        if (!PROJECTS.find((x) => x.id === project)) {
          return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
        }
        await this.env.VAULT.put(`notes:${project}`, notes);
        return { content: [{ type: "text", text: `Notes updated for ${project}.` }] };
      }
    );

    // create_task — append a task for a project
    this.server.tool(
      "create_task",
      "Add a task to a KeckerCo project",
      {
        project: z.string().describe("Project ID"),
        task: z.string().describe("Task description"),
        priority: z.enum(["low", "medium", "high"]).optional().describe("Task priority"),
      },
      async ({ project, task, priority = "medium" }) => {
        if (!PROJECTS.find((x) => x.id === project)) {
          return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
        }
        const existing = await this.env.VAULT.get(`tasks:${project}`) ?? "";
        const date = new Date().toISOString().split("T")[0];
        const newLine = `- [ ] [${priority}] ${task} _(added ${date})_`;
        await this.env.VAULT.put(`tasks:${project}`, existing ? `${existing}\n${newLine}` : newLine);
        return { content: [{ type: "text", text: `Task added to ${project}: ${task}` }] };
      }
    );

    // list_tasks — get open tasks for a project or all projects
    this.server.tool(
      "list_tasks",
      "List tasks for a project (or all projects if no project specified)",
      { project: z.string().optional().describe("Project ID, omit for all projects") },
      async ({ project }) => {
        const targets = project ? [PROJECTS.find((x) => x.id === project)].filter(Boolean) : PROJECTS;
        const parts: string[] = [];
        for (const p of targets) {
          if (!p) continue;
          const tasks = await this.env.VAULT.get(`tasks:${p.id}`);
          if (tasks) parts.push(`## ${p.id}\n${tasks}`);
        }
        const text = parts.length ? parts.join("\n\n") : "No tasks found.";
        return { content: [{ type: "text", text }] };
      }
    );

    // complete_task — mark a task done (replaces `- [ ]` with `- [x]` by line match)
    this.server.tool(
      "complete_task",
      "Mark a task as complete for a project by matching task text",
      {
        project: z.string().describe("Project ID"),
        task_text: z.string().describe("Partial text of the task to complete"),
      },
      async ({ project, task_text }) => {
        const existing = await this.env.VAULT.get(`tasks:${project}`);
        if (!existing) return { content: [{ type: "text", text: `No tasks found for ${project}.` }] };
        const updated = existing
          .split("\n")
          .map((line) => (line.includes(task_text) && line.startsWith("- [ ]") ? line.replace("- [ ]", "- [x]") : line))
          .join("\n");
        await this.env.VAULT.put(`tasks:${project}`, updated);
        return { content: [{ type: "text", text: `Marked done in ${project}: ${task_text}` }] };
      }
    );

    // get_github_issues — fetch open issues from a project's GitHub repo
    this.server.tool(
      "get_github_issues",
      "Get open GitHub issues for a KeckerCo project",
      {
        project: z.string().describe("Project ID"),
        limit: z.number().int().min(1).max(50).optional().describe("Max issues to return (default 10)"),
      },
      async ({ project, limit = 10 }) => {
        const p = PROJECTS.find((x) => x.id === project);
        if (!p) return { content: [{ type: "text", text: `Unknown project: ${project}` }] };
        try {
          const issues = await githubRequest(
            `/repos/${this.env.GITHUB_ORG}/${p.repo}/issues?state=open&per_page=${limit}`,
            this.env
          ) as Array<{ number: number; title: string; html_url: string; labels: Array<{ name: string }> }>;
          if (!issues.length) return { content: [{ type: "text", text: `No open issues in ${project}.` }] };
          const text = issues
            .map((i) => `#${i.number} ${i.title}\n  ${i.html_url}`)
            .join("\n\n");
          return { content: [{ type: "text", text }] };
        } catch (e) {
          return { content: [{ type: "text", text: `Error fetching issues: ${(e as Error).message}` }] };
        }
      }
    );
  }
}

export default {
  fetch(req: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(req.url);

    // Simple bearer token auth — set KECKER_MCP_TOKEN secret in wrangler
    const auth = req.headers.get("Authorization") ?? "";
    const token = (env as unknown as Record<string, string>)["KECKER_MCP_TOKEN"];
    if (token && auth !== `Bearer ${token}`) {
      return new Response("Unauthorized", { status: 401 });
    }

    return KeckerMCP.mount("/mcp").fetch(req, env, ctx);
  },
};
