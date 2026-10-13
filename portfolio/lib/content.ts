import { projectBundles } from "@/content/projects";
import { portfolio } from "@/content/portfolio";
import { profile, profileClaims } from "@/content/profile";
import { approachExamples, approachSteps } from "@/content/approach";
import { lenses, lensById } from "@/content/lenses";
import type { Asset, Claim, ClaimPlacement, LensId, ProjectBundle } from "@/content/types";
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
  if (project.slot === "candidate" && !SHOW_DRAFTS) {
    buildLog(`excluded project "${project.title}" (${project.slug}): candidate slot, draft only`);
    return false;
  }
  return true;
}

export function getProjects(): ProjectBundle[] {
  return projectBundles
    .filter(projectVisible)
    .slice()
    .sort((a, b) => a.project.sequence - b.project.sequence);
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

export function getLeadProject(): ProjectBundle | null {
  const projects = getProjects();
  return projects.find((b) => b.project.leadWork) ?? projects[0] ?? null;
}

export function getHomeFeatures(limit = 3): ProjectBundle[] {
  return getProjects().filter((b) => b.project.homeFeature && !b.project.leadWork).slice(0, limit);
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
  const asset = visibleAssets(bundle).find((a) => a.id === assetId);
  return asset ?? null;
}

export function getHeroAsset(bundle: ProjectBundle): Asset | null {
  return getAsset(bundle, bundle.project.heroAssetId);
}

export function getIndexAsset(bundle: ProjectBundle): Asset | null {
  return getAsset(bundle, bundle.project.indexAssetId) ?? getHeroAsset(bundle);
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

export function getProjectsForLens(lens: LensId): ProjectBundle[] {
  return getProjects().filter((b) => b.project.lenses.includes(lens));
}

export function getApproachExamples(stepId: string) {
  return approachExamples
    .filter((e) => e.step === stepId)
    .map((e) => ({ example: e, project: getProjectById(e.projectId) }))
    .filter((e) => e.project !== null) as { example: (typeof approachExamples)[number]; project: ProjectBundle }[];
}

export { portfolio, profile, approachSteps, lenses, lensById };
