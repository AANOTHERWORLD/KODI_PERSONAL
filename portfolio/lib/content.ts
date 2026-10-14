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
// Fail the build on a featured id that does not exist or a duplicated entry.
export function assertContentReferences() {
  const ids = new Set(projectBundles.map((b) => b.project.id));
  const slugs = projectBundles.map((b) => b.project.slug);
  if (new Set(slugs).size !== slugs.length) throw new Error("Duplicate project slug");
  for (const e of approachExamples) if (!ids.has(e.projectId)) throw new Error(`Approach example references missing project ${e.projectId}`);
  for (const b of projectBundles) {
    const p = b.project;
    if (p.relatedProject && !ids.has(p.relatedProject)) throw new Error(`${p.id}: relatedProject ${p.relatedProject} not found`);
    const assetIds = new Set(b.assets.map((a) => a.id));
    const refs = [p.heroAssetId, p.indexAssetId, ...b.decisions.flatMap((d) => d.assetIds), ...b.narrative.scaleTranslation.map((s) => s.assetId)].filter(Boolean) as string[];
    for (const r of refs) if (!assetIds.has(r)) throw new Error(`${p.id}: asset reference ${r} not found`);
  }
}

function assertSelections() {
  const known = new Set(projectBundles.map((b) => b.project.id));
  for (const id of SELECTED_WORK_IDS) if (!known.has(id)) throw new Error(`Selected work id not found: ${id}`);
  if (new Set(SELECTED_WORK_IDS).size !== SELECTED_WORK_IDS.length) throw new Error("Duplicate id in selected work");
}
export function getProjects(): ProjectBundle[] {
  return [...getCoreProjects(), ...getExtendedProjects()];
}

export function getCoreProjects(): ProjectBundle[] {
  return projectBundles.filter((b) => b.project.tier === "core").filter(projectVisible).sort(bySequence);
}

// Editorial selection, independent of the general project sequence. Order matters.
export const HOMEPAGE_IDS = ["tinder-hq", "intuit-turbotax-retail", "lsd-running", "google-gso-home-of-the-internet", "google-room-98", "kilroy-oyster-point"];
export const SELECTED_WORK_IDS = [...HOMEPAGE_IDS, "openai", "watt-plaza"];

const byIds = (ids: string[]) => (assertSelections(), ids).map((id) => getCoreProjects().find((b) => b.project.id === id)).filter((b): b is ProjectBundle => !!b);

export function getHomepageProjects(): ProjectBundle[] {
  return byIds(HOMEPAGE_IDS);
}

// Work page order: selected projects in editorial order, then the rest in their existing sequence.
export function getWorkGroups(): { selected: ProjectBundle[]; further: ProjectBundle[] } {
  const selected = byIds(SELECTED_WORK_IDS);
  const further = getCoreProjects().filter((b) => !SELECTED_WORK_IDS.includes(b.project.id));
  return { selected, further };
}

export function getWorkOrder(): ProjectBundle[] {
  const { selected, further } = getWorkGroups();
  return [...selected, ...further];
}

export function getExtendedProjects(): ProjectBundle[] {
  return projectBundles.filter((b) => b.project.tier === "extended").filter(projectVisible).sort(bySequence);
}

// Static export requires at least one generated route for /work/[slug]. When no project has
// cleared the gates yet, a single placeholder route explains the state instead of failing the build.
export const PLACEHOLDER_SLUG = "coming-soon";

export function getAllProjectSlugs(): string[] {
  assertContentReferences();
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
// The landing field features project imagery: photographs and renders, never diagrams or plans.
// Each core project contributes its hero (or first image) first, then projects with more imagery
// contribute a second and a third, smaller tile, until the limit. Projects whose only assets are diagrams
// (platform maps, concept diagrams) stay out of the field and are reached from Work.
export const LANDING_TILE_LIMIT = 20;
const IMAGE_TYPES: Asset["type"][] = ["photo", "render"];

export interface LandingTile {
  key: string;
  bundle: ProjectBundle;
  asset: Asset | null;
  spec: TileSpec;
  label: string;
  // 1 to 5: drives the tile's size in the field (see components/ScrollStage.tsx).
  size: number;
}

export function getLandingTiles(): LandingTile[] {
  const rounds: LandingTile[][] = [[], [], []];
  const sized = (project: ProjectBundle["project"]) => 1 + ((project.tileSize - 1) * 4) / 3;
  for (const bundle of getCoreProjects()) {
    if (!bundle.project.landingTile) continue;
    const images = visibleAssets(bundle).filter((a) => IMAGE_TYPES.includes(a.type));
    if (!images.length) continue;
    const hero = images.find((a) => a.id === bundle.project.heroAssetId) ?? images[0];
    const second = images.find((a) => a.id !== hero.id && a.id === bundle.project.indexAssetId) ?? images.find((a) => a.id !== hero.id);
    const base: TileSpec = bundle.project.tiles?.[0] ?? { x: 0, y: 0, depth: 2, order: bundle.project.sequence };
    rounds[0].push({ key: `${bundle.project.id}-0`, bundle, asset: hero, spec: { ...base, order: bundle.project.sequence }, label: bundle.project.title, size: sized(bundle.project) });
    if (second) rounds[1].push({ key: `${bundle.project.id}-1`, bundle, asset: second, spec: { ...base, order: bundle.project.sequence }, label: bundle.project.title, size: Math.max(1, sized(bundle.project) - 1.5) });
    const third = images.find((a) => a.id !== hero.id && a.id !== second?.id);
    if (third) rounds[2].push({ key: `${bundle.project.id}-2`, bundle, asset: third, spec: { ...base, order: bundle.project.sequence }, label: bundle.project.title, size: Math.max(1, sized(bundle.project) - 2.5) });
  }
  return [...rounds[0], ...rounds[1], ...rounds[2]].slice(0, LANDING_TILE_LIMIT);
}

export { portfolio, profile, approachSteps, lenses, lensById };
