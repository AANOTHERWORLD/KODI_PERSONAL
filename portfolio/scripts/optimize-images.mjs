// Build-time image pipeline.
//
// Reads every source image in public/projects/<slug>/ and writes WebP renditions at a few
// responsive widths into public/generated/<slug>/. A manifest with intrinsic dimensions is
// written to content/generated/image-manifest.json so the Picture component can emit
// srcset, sizes, width and height without touching the images at request time.
//
// Source images are never modified. Generated folders are gitignored.
// Run automatically as the npm "prebuild" step, or directly with `npm run images`.

import fs from "node:fs/promises";
import path from "node:path";
import sharp from "sharp";

const ROOT = process.cwd();
const SOURCE_DIR = path.join(ROOT, "public", "projects");
const OUTPUT_DIR = path.join(ROOT, "public", "generated");
const MANIFEST_DIR = path.join(ROOT, "content", "generated");
const MANIFEST_PATH = path.join(MANIFEST_DIR, "image-manifest.json");

const WIDTHS = [480, 960, 1440, 2000, 2800];
const QUALITY = 82;
const SOURCE_EXT = new Set([".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff"]);
const DEBUG = process.env.NEXT_PUBLIC_DEBUG === "true" || process.argv.includes("--verbose");

function log(...args) {
  if (DEBUG) console.log("[images]", ...args);
}

async function exists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function listSources() {
  const out = [];
  if (!(await exists(SOURCE_DIR))) return out;
  const slugs = await fs.readdir(SOURCE_DIR, { withFileTypes: true });
  for (const slugEntry of slugs) {
    if (!slugEntry.isDirectory()) continue;
    const slug = slugEntry.name;
    const files = await fs.readdir(path.join(SOURCE_DIR, slug));
    for (const file of files) {
      if (!SOURCE_EXT.has(path.extname(file).toLowerCase())) continue;
      out.push({ slug, file, abs: path.join(SOURCE_DIR, slug, file) });
    }
  }
  return out;
}

async function processOne(src, manifest) {
  const key = `${src.slug}/${src.file}`;
  const base = path.parse(src.file).name;
  const outDir = path.join(OUTPUT_DIR, src.slug);
  await fs.mkdir(outDir, { recursive: true });

  const image = sharp(src.abs, { failOn: "none" }).rotate();
  const meta = await image.metadata();
  if (!meta.width || !meta.height) {
    console.warn(`[images] skipped ${key}: could not read dimensions`);
    return;
  }
  const srcStat = await fs.stat(src.abs);
  const renditions = [];

  for (const width of WIDTHS) {
    if (width > meta.width && width !== WIDTHS[0]) continue;
    const targetWidth = Math.min(width, meta.width);
    const outFile = `${base}-${targetWidth}.webp`;
    const outAbs = path.join(outDir, outFile);
    const height = Math.round((meta.height / meta.width) * targetWidth);

    let fresh = false;
    if (await exists(outAbs)) {
      const outStat = await fs.stat(outAbs);
      fresh = outStat.mtimeMs >= srcStat.mtimeMs;
    }
    if (!fresh) {
      await sharp(src.abs, { failOn: "none" })
        .rotate()
        .resize({ width: targetWidth, withoutEnlargement: true })
        .webp({ quality: QUALITY, effort: 4 })
        .toFile(outAbs);
      log("wrote", `${src.slug}/${outFile}`);
    }
    renditions.push({ width: targetWidth, height, src: `/generated/${src.slug}/${outFile}` });
  }

  manifest[key] = {
    width: meta.width,
    height: meta.height,
    renditions: renditions.sort((a, b) => a.width - b.width),
  };
}

async function main() {
  const started = Date.now();
  const sources = await listSources();
  const manifest = {};
  for (const src of sources) {
    try {
      await processOne(src, manifest);
    } catch (error) {
      console.warn(`[images] failed ${src.slug}/${src.file}:`, error?.message ?? error);
    }
  }
  await fs.mkdir(MANIFEST_DIR, { recursive: true });
  await fs.writeFile(MANIFEST_PATH, JSON.stringify(manifest, null, 2));
  console.log(
    `[images] ${Object.keys(manifest).length} source images processed in ${Math.round((Date.now() - started) / 1000)}s`,
  );
}

main().catch((error) => {
  console.error("[images] pipeline failed:", error);
  process.exit(1);
});
