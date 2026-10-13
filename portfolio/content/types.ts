// Content model for the portfolio. These records are the single source of truth for the site
// and for a future PDF edition. Adding a project means adding records here, never editing layout.
// The shape is deliberately plain so it can be swapped for a headless CMS (Sanity) later by
// replacing the loader in lib/content.ts without touching components.

export type LensId = "culture-strategy" | "architecture-place" | "interiors-behavior" | "brand-detail";

export interface Lens {
  id: LensId;
  name: string;
  short: string;
  question: string;
  numeral: string;
}

export type ProjectStatus = "completed" | "in-progress" | "concept";
export type Permission = "confirmed" | "pending";
export type ClaimStatus = "verified" | "awaiting" | "omit";
export type AssetType = "photo" | "render" | "concept" | "plan" | "diagram" | "process";
export type RosterSlot = "core" | "optional" | "candidate";

export interface Portfolio {
  name: string;
  descriptor: string;
  headline: string;
  positioning: string;
  email: string;
  linkedin: string;
  location: string;
  availability: string;
  versionDate: string;
  copyrightHolder: string;
}

export interface Project {
  id: string;
  title: string;
  slug: string;
  thesis: string;
  clientDisplayName: string;
  practice: string;
  location: string;
  years: string;
  status: ProjectStatus;
  statusNote?: string;
  role: string;
  scope: string;
  team: string[];
  collaborators: string[];
  lenses: LensId[];
  portfolioRole: string;
  sequence: number;
  tileSize: 1 | 2 | 3 | 4;
  homeFeature: boolean;
  leadWork?: boolean;
  slot: RosterSlot;
  relatedProject: string;
  permission: Permission;
  permissionNote?: string;
  heroAssetId: string;
  indexAssetId?: string;
}

export interface ScaleStep {
  lens: LensId;
  assetId?: string;
  caption: string;
}

export interface Narrative {
  projectId: string;
  challenge: string[];
  insight: string[];
  vision: string[];
  scaleTranslation: ScaleStep[];
  leadership: string[];
  leadershipMoment?: string;
  outcome: string[];
  reflection?: string;
  photographyCredit?: string;
  imageCredit?: string;
  involvement: string;
}

export interface Decision {
  id: string;
  projectId: string;
  title: string;
  question: string;
  choice: string;
  rationale: string;
  tradeoff: string;
  personalContribution?: string;
  assetIds: string[];
}

export type ClaimPlacement =
  | "role"
  | "leadership"
  | "outcome"
  | "credits"
  | "context"
  | "profile-bio"
  | "profile-leadership"
  | "profile-experience";

export interface Claim {
  id: string;
  projectId: string | "profile";
  placement: ClaimPlacement;
  wording: string;
  evidenceSource: string;
  verifier: string;
  status: ClaimStatus;
}

export interface Asset {
  id: string;
  projectId: string;
  file: string;
  type: AssetType;
  caption: string;
  alt: string;
  creator: string;
  credit: string;
  permission: Permission;
  lens?: LensId;
}

export interface ExperienceItem {
  period: string;
  title: string;
  organisation: string;
  note?: string;
}

export interface Profile {
  bio: string[];
  currentTitle: string;
  careerNarrative: string[];
  workingStyle: string[];
  leadershipClaimIds: string[];
  experience: ExperienceItem[];
  credentials: string[];
  portrait?: string;
  cvReference: string;
}

export interface ApproachStep {
  id: string;
  number: number;
  title: string;
  summary: string;
}

export interface ApproachExample {
  step: string;
  projectId: string;
  example: string;
}

export interface ProjectBundle {
  project: Project;
  narrative: Narrative;
  decisions: Decision[];
  assets: Asset[];
  claims: Claim[];
}
