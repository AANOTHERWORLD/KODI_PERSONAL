import type { NextConfig } from "next";

// Optional subpath hosting (for example GitHub Pages without a custom domain).
// Set NEXT_PUBLIC_BASE_PATH="/repo-name" at build time. Leave it unset for root hosting.
const rawBasePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
const basePath = rawBasePath === "/" ? "" : rawBasePath.replace(/\/$/, "");

const nextConfig: NextConfig = {
  // Fully static export: `next build` writes a self-contained /out folder.
  output: "export",
  // Routes resolve as folders (/work/index.html), which every static host serves cleanly.
  trailingSlash: true,
  basePath: basePath || undefined,
  assetPrefix: basePath || undefined,
  images: {
    // Runtime image optimization is unavailable in static export.
    // Optimization happens at build time in scripts/optimize-images.mjs (sharp).
    unoptimized: true,
  },
  reactStrictMode: true,
  poweredByHeader: false,
};

export default nextConfig;
