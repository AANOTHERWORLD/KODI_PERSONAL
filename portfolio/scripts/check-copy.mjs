// Guards the "no em dash" rule across code, content, and docs.
// Run with `npm run check:copy`. Exits non-zero when an em dash (U+2014) is found.

import fs from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const SKIP_DIRS = new Set(["node_modules", ".next", "out", "public", ".git"]);
const EXT = new Set([".ts", ".tsx", ".mjs", ".js", ".css", ".md", ".json"]);
const EM_DASH = String.fromCharCode(0x2014);

async function walk(dir, hits) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(abs, hits);
      continue;
    }
    if (!EXT.has(path.extname(entry.name))) continue;
    const text = await fs.readFile(abs, "utf8");
    const lines = text.split("\n");
    lines.forEach((line, index) => {
      if (line.includes(EM_DASH)) hits.push(`${path.relative(ROOT, abs)}:${index + 1}`);
    });
  }
}

const hits = [];
await walk(ROOT, hits);
if (hits.length) {
  console.error("Em dash found in:\n" + hits.join("\n"));
  process.exit(1);
}
console.log("check:copy passed: no em dashes found.");
