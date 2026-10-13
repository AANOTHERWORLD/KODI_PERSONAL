// Prefix for public asset URLs when the site is hosted under a subpath.
const raw = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
export const BASE_PATH = raw === "/" ? "" : raw.replace(/\/$/, "");

export function withBasePath(publicPath: string): string {
  if (!publicPath.startsWith("/")) return publicPath;
  return `${BASE_PATH}${publicPath}`;
}
