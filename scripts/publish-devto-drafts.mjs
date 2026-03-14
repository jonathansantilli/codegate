#!/usr/bin/env node

import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const DEFAULT_TOPICS_DIR = "docs/marketing/topics";
const DEFAULT_MANIFEST = "docs/marketing/devto-drafts-manifest.json";
const DEVTO_BASE_URL = "https://dev.to/api";
const USER_AGENT = "codegate-devto-drafts/1.0 (+https://github.com/jonathansantilli/codegate)";

function parseArgs(argv) {
  const args = {
    apply: false,
    topicsDir: DEFAULT_TOPICS_DIR,
    manifest: DEFAULT_MANIFEST,
    series: process.env.DEVTO_SERIES ?? "CodeGate Security Series",
    tags: process.env.DEVTO_TAGS ?? "codegate,security,ai,devtools",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--apply") {
      args.apply = true;
    } else if (token === "--topics-dir") {
      args.topicsDir = argv[i + 1];
      i += 1;
    } else if (token === "--manifest") {
      args.manifest = argv[i + 1];
      i += 1;
    } else if (token === "--series") {
      args.series = argv[i + 1];
      i += 1;
    } else if (token === "--tags") {
      args.tags = argv[i + 1];
      i += 1;
    } else if (token === "--help" || token === "-h") {
      globalThis.console.log(`Usage:
  node scripts/publish-devto-drafts.mjs [--apply] [--topics-dir <path>] [--manifest <path>] [--series <name>] [--tags <comma,separated>]

Behavior:
  - Default mode is dry-run (no DEV post is created).
  - Use --apply to create DEV draft posts.
  - Requires DEVTO_API_KEY when --apply is set.

Env vars:
  DEVTO_API_KEY   API key for DEV
  DEVTO_SERIES    Optional series name (default: "${args.series}")
  DEVTO_TAGS      Optional tags CSV (default: "${args.tags}")`);
      process.exit(0);
    }
  }

  return args;
}

function sleep(ms) {
  return new Promise((resolve) => {
    globalThis.setTimeout(resolve, ms);
  });
}

async function devtoRequest(apiKey, pathname, { method = "GET", body } = {}) {
  const url = `${DEVTO_BASE_URL}${pathname}`;
  const maxAttempts = 4;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const res = await globalThis.fetch(url, {
      method,
      headers: {
        "api-key": apiKey,
        "content-type": "application/json",
        "user-agent": USER_AGENT,
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (res.status === 429 && attempt < maxAttempts) {
      const retryAfter = Number(res.headers.get("retry-after") ?? "2");
      await sleep(Math.max(1, retryAfter) * 1000);
      continue;
    }

    const text = await res.text();
    let payload;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = text;
    }

    if (!res.ok) {
      const pretty = typeof payload === "string" ? payload : JSON.stringify(payload);
      throw new Error(`DEV API ${method} ${pathname} failed (${res.status}): ${pretty}`);
    }

    return payload;
  }

  throw new Error(`DEV API ${method} ${pathname} exhausted retry attempts`);
}

async function listDrafts(apiKey) {
  const drafts = [];
  let page = 1;
  const perPage = 100;

  while (page <= 20) {
    const items = await devtoRequest(
      apiKey,
      `/articles/me/unpublished?page=${page}&per_page=${perPage}`,
    );
    if (!Array.isArray(items) || items.length === 0) {
      break;
    }
    drafts.push(...items);
    if (items.length < perPage) {
      break;
    }
    page += 1;
  }

  return drafts;
}

async function discoverBlogs(topicsDir) {
  const dirs = await readdir(topicsDir, { withFileTypes: true });
  const items = [];

  for (const dirent of dirs
    .filter((d) => d.isDirectory())
    .sort((a, b) => a.name.localeCompare(b.name))) {
    const blogPath = path.join(topicsDir, dirent.name, "blog.md");
    try {
      const details = await stat(blogPath);
      if (!details.isFile()) {
        continue;
      }
    } catch {
      continue;
    }

    const markdown = await readFile(blogPath, "utf8");
    const heading = markdown
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.startsWith("# "));
    const title = heading ? heading.replace(/^#\s+/, "").trim() : dirent.name.replace(/-/g, " ");
    items.push({
      slug: dirent.name,
      title,
      blogPath,
      bodyMarkdown: markdown,
    });
  }

  return items;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const topicsDirAbs = path.resolve(args.topicsDir);
  const manifestAbs = path.resolve(args.manifest);
  const apiKey = process.env.DEVTO_API_KEY;

  if (args.apply && !apiKey) {
    throw new Error("DEVTO_API_KEY is required when --apply is used");
  }

  const blogs = await discoverBlogs(topicsDirAbs);
  if (blogs.length === 0) {
    throw new Error(`No blog.md files found under ${topicsDirAbs}`);
  }

  const existingDraftsByTitle = new Map();
  if (args.apply) {
    const existingDrafts = await listDrafts(apiKey);
    for (const draft of existingDrafts) {
      if (draft && typeof draft.title === "string") {
        existingDraftsByTitle.set(draft.title, draft);
      }
    }
  }

  const results = [];
  for (const blog of blogs) {
    if (existingDraftsByTitle.has(blog.title)) {
      const draft = existingDraftsByTitle.get(blog.title);
      results.push({
        slug: blog.slug,
        title: blog.title,
        status: "skipped_existing",
        id: draft?.id ?? null,
        url: draft?.url ?? null,
      });
      continue;
    }

    if (!args.apply) {
      results.push({
        slug: blog.slug,
        title: blog.title,
        status: "planned",
      });
      continue;
    }

    try {
      const created = await devtoRequest(apiKey, "/articles", {
        method: "POST",
        body: {
          article: {
            title: blog.title,
            body_markdown: blog.bodyMarkdown,
            published: false,
            series: args.series,
            tags: args.tags,
          },
        },
      });

      results.push({
        slug: blog.slug,
        title: blog.title,
        status: "created",
        id: created?.id ?? null,
        url: created?.url ?? null,
      });
      // Small pacing to stay friendly with rate limits.
      await sleep(200);
    } catch (error) {
      results.push({
        slug: blog.slug,
        title: blog.title,
        status: "failed",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    mode: args.apply ? "apply" : "dry-run",
    topicsDir: topicsDirAbs,
    series: args.series,
    tags: args.tags,
    total: results.length,
    created: results.filter((r) => r.status === "created").length,
    planned: results.filter((r) => r.status === "planned").length,
    skippedExisting: results.filter((r) => r.status === "skipped_existing").length,
    failed: results.filter((r) => r.status === "failed").length,
    results,
  };

  await mkdir(path.dirname(manifestAbs), { recursive: true });
  await writeFile(manifestAbs, JSON.stringify(summary, null, 2) + "\n", "utf8");

  globalThis.console.log(
    JSON.stringify(
      {
        mode: summary.mode,
        total: summary.total,
        created: summary.created,
        planned: summary.planned,
        skippedExisting: summary.skippedExisting,
        failed: summary.failed,
        manifest: manifestAbs,
      },
      null,
      2,
    ),
  );

  if (summary.failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  globalThis.console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
