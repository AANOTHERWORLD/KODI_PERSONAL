// Content model for the portfolio. These records are the single source of truth for the site
// and for the PDF edition. Adding a project means adding records here, never editing layout.
// The shape is deliberately plain so it can be swapped for a headless CMS (Sanity) later by
// replacing the loader in lib/content.ts without touching components.

export type LensId = "culture-strategy" | "architecture-place" | "interiors-behavior" | "brand-detail";

export interface Lens {
  id: LensId;
  name: string;
  short: string;
  // What the lens asks of a project, used on project pages.
  question: string;
  // What the lens does, used on Home and Approach.
  role: string;
  numeral: string;
}

export type ProjectStatus = "completed" | "in-progress" | "concept";
export type Permission = "confirmed" | "pending";
export type ClaimStatus = "verified" | "awaiting" | "omit";
export type AssetType = "photo" | "render" | "concept" | "plan" | "diagram" | "process" | "graphic";
export type Tier = "core" | "extended";
export type CaseStudyKind = "full" | "light";

export interface Portfolio {
  name: string;
  wordmark: string;
  descriptor: string;
  headline: string;
  // H1 on Home. The explanation beneath it is statementBody.
  statement: string;
  statementBody: string;
  leadershipHeading: string;
  leadershipProof: string[];
  // One line under the name: discipline positioning, distinct from the employment title.
  tagline: string;
  positioning: string;
  email: string;
  emailSubject: string;
  // Social links render only when a verified profile URL is present.
  linkedin?: string;
  instagram?: string;
  location: string;
  availability: string;
  internationalAvailability: string;
  versionDate: string;
  copyrightHolder: string;
  workRangeLabel: string;
}

// A tile in the landing field. x and y are percentages of the stage (x of width, y of the
// stage height). depth 1 to 3 sets scroll speed (3 is fastest, nearest). order sets the
// interleave so core projects land in the first two screens. assetId overrides the hero.
export interface TileSpec {
  x: number;
  y: number;
  depth: 1 | 2 | 3;
  order: number;
  assetId?: string;
  label?: string;
}

export interface Project {
  id: string;
  title: string;
  slug: string;
  tier: Tier;
  caseStudy: CaseStudyKind;
  inPdf: boolean;
  landingTile: boolean;
  tiles?: TileSpec[];
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
  // What the project is, in plain words, and the disciplines involved. Shown on cards and in the opening.
  typeLabel: string;
  disciplines: string;
  sequence: number;
  tileSize: 1 | 2 | 3 | 4;
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
  featuredPublication?: {
    assetId: string;
    title: string;
    description: string;
    url: string;
  };
  // Optional short labels for the summary paragraphs ("The ambition", "My leadership", ...).
  summaryLabels?: string[];
  // Longer account of how the work developed, shown after the opening.
  story?: string[];
  // Light pages use summary (about 150 to 300 words). Full pages use the sections below.
  summary?: string[];
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
  // Explicit image for each narrative section of the full template. An asset id pins the image;
  // null makes the section text-only. A section left out falls back to the next unused image.
  // Reordering the gallery never changes an assigned pairing.
  // Optional project-specific headings for the full template's narrative sections.
  sectionTitles?: Partial<Record<"story" | "challenge" | "vision" | "leadership" | "outcome", string>>;
  sectionImages?: Partial<Record<"story" | "challenge" | "vision" | "leadership" | "outcome", string | null>>;
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
  | "profile-recognition"
  | "profile-experience";

export interface Claim {
  id: string;
  projectId: string | "profile";
  placement: ClaimPlacement;
  wording: string;
  evidenceSource: string;
  // Optional public citation for the claim (an issue, an official result, or a project page).
  url?: string;
  verifier: string;
  status: ClaimStatus;
}

export interface Asset {
  motion?: { file: string; loop?: boolean; muted?: boolean };
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
  title: string;
  practice: string;
  years: string;
}

export interface Profile {
  name: string;
  currentTitle: string;
  bio: string;
  aboutStatement: string;
  leadershipStatement: string;
  leadershipSummary: string;
  careerNarrative: string[];
  aboutIntro: string[];
  leadershipSnapshot: string[];
  leadershipNarrative: string[];
  workingStyle: string[];
  experience: ExperienceItem[];
  recognitionClaimIds: string[];
  leadershipClaimIds: string[];
  credentials: string[];
  portraitAssetId: string;
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
