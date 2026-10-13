import fs from "node:fs";
import path from "node:path";
import { withBasePath } from "./basePath";

export interface Rendition {
  width: number;
  height: number;
  src: string;
}

export interface ImageRecord {
  width: number;
  height: number;
  renditions: Rendition[];
}

type Manifest = Record<string, ImageRecord>;

let cached: Manifest | null = null;

// Reads the manifest written by scripts/optimize-images.mjs. When the pipeline has not run
// (for example a fresh `next dev`), the Picture component falls back to the source image.
export function getImageManifest(): Manifest {
  if (cached) return cached;
  try {
    const p = path.join(process.cwd(), "content", "generated", "image-manifest.json");
    cached = JSON.parse(fs.readFileSync(p, "utf8")) as Manifest;
  } catch {
    cached = {};
  }
  return cached;
}

export interface ResolvedImage {
  src: string;
  srcSet?: string;
  width: number;
  height: number;
  vector?: boolean;
}

function sourcePath(file: string) {
  return path.join(process.cwd(), "public", "projects", file);
}

function svgDimensions(abs: string): { width: number; height: number } {
  try {
    const head = fs.readFileSync(abs, "utf8").slice(0, 2000);
    const viewBox = head.match(/viewBox="([\d.\s-]+)"/);
    if (viewBox) {
      const parts = viewBox[1].trim().split(/\s+/).map(Number);
      if (parts.length === 4 && parts[2] > 0 && parts[3] > 0) return { width: parts[2], height: parts[3] };
    }
    const w = head.match(/\swidth="(\d+)"/);
    const h = head.match(/\sheight="(\d+)"/);
    if (w && h) return { width: Number(w[1]), height: Number(h[1]) };
  } catch {
    // fall through to a safe default
  }
  return { width: 1600, height: 1000 };
}

export function resolveImage(file: string): ResolvedImage | null {
  const abs = sourcePath(file);
  if (file.toLowerCase().endsWith(".svg")) {
    if (!fs.existsSync(abs)) return null;
    const dims = svgDimensions(abs);
    return { src: withBasePath(`/projects/${file}`), ...dims, vector: true };
  }
  const manifest = getImageManifest();
  const record = manifest[file];
  if (record && record.renditions.length) {
    const largest = record.renditions[record.renditions.length - 1];
    return {
      src: withBasePath(largest.src),
      srcSet: record.renditions.map((r) => `${withBasePath(r.src)} ${r.width}w`).join(", "),
      width: record.width,
      height: record.height,
    };
  }
  // Fallback: serve the untouched source. Dimensions are unknown here, so use a neutral
  // 3:2 box to limit layout shift; the pipeline normally supplies the real values.
  if (!fs.existsSync(abs)) return null;
  return { src: withBasePath(`/projects/${file}`), width: 1500, height: 1000 };
}
