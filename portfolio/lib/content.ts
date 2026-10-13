import { projectBundles } from "@/content/projects";
import { portfolio } from "@/content/portfolio";
import { profile, profileAssets, profileClaims } from "@/content/profile";
import { approachExamples, approachSteps } from "@/content/approach";
import { lenses, lensById } from "@/content/lenses";
import type { Asset, Claim, ClaimPlacement, LensId, ProjectBundle, TileSpec } from "@/content/types";
import { buildLog } from "./debug";

// Content loader and governance gates.
//
// Draft mode: NEXT_PUBLIC_SHOW_DRAFTS=true renders pending projects and assets and awaiting
// claims, each with a visible marker. Production builds default to off.
//
// Verification gate: only claims with status "verified" render in production.
// Permission gate: projects and assets with permission "pending" are excluded in production.
// Every exclusion is logged during the build so nothing disappears silently.

export const SHOW_DRAFTS = process.env.NEXT_PUBLIC_SHOW_DRAFTS === "true";

export function isDraftMode(): boolean {
  return SHOW_DRAFTS;
}

function projectVisible(bundle: ProjectBundle): boolean {
  const { project } = bundle;
  if (project.permission === "pending" && !SHOW_DRAFTS) {
    buildLog(`excluded project "${project.title}" (${project.slug}): permission pending`);
    return false;
  }
  return true;
}

function bySequence(a: ProjectBundle, b: ProjectBundle) {
  return a.project.sequence - b.project.sequence;
}

// Core projects in sequence, then extended projects in their own sequence.
export function getProjects(): ProjectBundle[] {
  return [...getCoreProjects(), ...getExtendedProjects()];
}

export function getCoreProjects(): ProjectBundle[] {
  return projectBundles.filter((b) => b.project.tier === "core").filter(projectVisible).sort(bySequence);
}

export function getExtendedProjects(): ProjectBundle[] {
  return projectBundles.filter((b) => b.project.tier === "extended").filter(projectVisible).sort(bySequence);
}

// Static export requires at least one generated route for /work/[slug]. When no project has
// cleared the gates yet, a single placeholder route explains the state instead of failing the build.
export const PLACEHOLDER_SLUG = "coming-soon";

export function getAllProjectSlugs(): string[] {
  const slugs = getProjects().map((b) => b.project.slug);
  if (!slugs.length) {
    buildLog(`no projects cleared for publication; generating placeholder route /work/${PLACEHOLDER_SLUG}/`);
    return [PLACEHOLDER_SLUG];
  }
  return slugs;
}

export function getProject(slug: string): ProjectBundle | null {
  return getProjects().find((b) => b.project.slug === slug) ?? null;
}

export function getProjectById(id: string): ProjectBundle | null {
  return getProjects().find((b) => b.project.id === id) ?? null;
}

export function visibleAssets(bundle: ProjectBundle): Asset[] {
  return bundle.assets.filter((asset) => {
    if (asset.permission === "pending" && !SHOW_DRAFTS) {
      buildLog(`excluded asset "${asset.id}" (${bundle.project.slug}): permission pending`);
      return false;
    }
    return true;
  });
}

export function getAsset(bundle: ProjectBundle, assetId: string | undefined): Asset | null {
  if (!assetId) return null;
  return visibleAssets(bundle).find((a) => a.id === assetId) ?? null;
}

export function getHeroAsset(bundle: ProjectBundle): Asset | null {
  return getAsset(bundle, bundle.project.heroAssetId);
}

export function getIndexAsset(bundle: ProjectBundle): Asset | null {
  return getAsset(bundle, bundle.project.indexAssetId) ?? getHeroAsset(bundle);
}

export function getProfileAsset(id: string): Asset | null {
  const asset = profileAssets.find((a) => a.id === id);
  if (!asset) return null;
  if (asset.permission === "pending" && !SHOW_DRAFTS) {
    buildLog(`excluded profile asset "${asset.id}": permission pending`);
    return null;
  }
  return asset;
}

function claimVisible(claim: Claim, scope: string): boolean {
  if (claim.status === "omit") {
    buildLog(`omitted claim "${claim.id}" (${scope})`);
    return false;
  }
  if (claim.status === "awaiting" && !SHOW_DRAFTS) {
    buildLog(`excluded claim "${claim.id}" (${scope}): awaiting verification`);
    return false;
  }
  return true;
}

export function getClaims(bundle: ProjectBundle, placement: ClaimPlacement): Claim[] {
  return bundle.claims.filter((c) => c.placement === placement && claimVisible(c, bundle.project.slug));
}

export function getProfileClaims(placement: ClaimPlacement): Claim[] {
  return profileClaims.filter((c) => c.placement === placement && claimVisible(c, "profile"));
}

export function getProfileClaimsById(ids: string[]): Claim[] {
  return ids
    .map((id) => profileClaims.find((c) => c.id === id))
    .filter((c): c is Claim => !!c && claimVisible(c, "profile"));
}

export function getLensCounts(): Record<LensId, number> {
  const all = getProjects();
  return Object.fromEntries(lenses.map((l) => [l.id, all.filter((b) => b.project.lenses.includes(l.id)).length])) as Record<LensId, number>;
}

export function getApproachExamples(stepId: string) {
  return approachExamples
    .filter((e) => e.step === stepId)
    .map((e) => ({ example: e, project: getProjectById(e.projectId) }))
    .filter((e) => e.project !== null) as { example: (typeof approachExamples)[number]; project: ProjectBundle }[];
}

// Landing tile field. The stage is one viewport tall, so only a handful of tiles fit around the
// statement. A project appears when it has landingTile and explicit tile coordinates (x and y as
// percentages of the viewport, depth 1 to 3 for drift speed, order for stacking). The field is
// capped at LANDING_TILE_LIMIT tiles, taken in order. Everything else is reachable from Work.
export const LANDING_TILE_LIMIT = 6;

export interface LandingTile {
  key: string;
  bundle: ProjectBundle;
  asset: Asset | null;
  spec: TileSpec;
  label: string;
}

export function getLandingTiles(): LandingTile[] {
  const out: LandingTile[] = [];
  for (const bundle of getProjects()) {
    if (!bundle.project.landingTile || !bundle.project.tiles?.length) continue;
    bundle.project.tiles.forEach((spec, i) => {
      out.push({
        key: `${bundle.project.id}-${i}`,
        bundle,
        asset: getAsset(bundle, spec.assetId) ?? getIndexAsset(bundle),
        spec,
        label: spec.label ?? bundle.project.title,
      });
    });
  }
  return out.sort((a, b) => a.spec.order - b.spec.order).slice(0, LANDING_TILE_LIMIT);
}

export { portfolio, profile, approachSteps, lenses, lensById };
