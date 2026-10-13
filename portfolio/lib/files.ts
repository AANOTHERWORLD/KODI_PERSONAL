import fs from "node:fs";
import path from "node:path";

// Build-time existence checks for optional downloads. Static export runs these during
// `next build`, so a link renders only when the file is actually in /public.
function publicFileExists(name: string): boolean {
  try {
    return fs.existsSync(path.join(process.cwd(), "public", name));
  } catch {
    return false;
  }
}

export function getDownloads() {
  return {
    portfolioPdf: publicFileExists("portfolio.pdf") ? "/portfolio.pdf" : null,
    cvPdf: publicFileExists("cv.pdf") ? "/cv.pdf" : null,
  };
}
