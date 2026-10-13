import type { Asset, Decision, LensId, Narrative, Project, ProjectBundle, Claim } from "../types";

// Extended projects for the website only. Facts marked PLACEHOLDER are visible stand-in copy,
// and every project stays permission: pending until Jamel confirms it, so these pages render
// in draft mode only until then.

type Seed = {
  id: string;
  title: string;
  lenses: LensId[];
  sequence: number;
  tileSize: 1 | 2 | 3 | 4;
  kind: string;
  tiles?: Project["tiles"];
  note: string;
};

const seeds: Seed[] = [
  { id: "club-gemini", title: "Club Gemini", lenses: ["brand-detail", "interiors-behavior"], sequence: 2, tileSize: 2, kind: "Experiential", note: "PLACEHOLDER: client descriptor, year, idea, what was made." },
  { id: "napa-retreat", title: "Napa Leadership Retreat", lenses: ["culture-strategy", "brand-detail"], sequence: 3, tileSize: 2, kind: "Experiential event", note: "PLACEHOLDER: client descriptor, year, idea, what was made." },
  { id: "april-jean", title: "Bar April Jean", lenses: ["brand-detail", "interiors-behavior"], sequence: 4, tileSize: 2, kind: "Hospitality", note: "PLACEHOLDER: facts; confirm this is Jamel's work." },
  { id: "place-at-table", title: "A Place At The Table", lenses: ["culture-strategy"], sequence: 5, tileSize: 1, kind: "Strategy and concept", note: "PLACEHOLDER: facts." },
  { id: "the-mark", title: "The Mark", lenses: ["brand-detail"], sequence: 6, tileSize: 1, kind: "To be confirmed", note: "Confirm this is Jamel's project and supply facts, or remove." },
  { id: "mama-rouge", title: "Mama Rouge", lenses: ["brand-detail"], sequence: 7, tileSize: 1, kind: "To be confirmed", note: "Confirm this is Jamel's project and supply facts, or remove." },
  { id: "lightspark", title: "Lightspark", lenses: ["brand-detail"], sequence: 8, tileSize: 1, kind: "To be confirmed", note: "Confirm this is Jamel's project and supply facts, or remove." },
];

function build(seed: Seed): ProjectBundle {
  const project: Project = {
    id: seed.id,
    title: seed.title,
    slug: seed.id,
    tier: "extended",
    caseStudy: "light",
    inPdf: false,
    landingTile: true,
    tiles: seed.tiles,
    thesis: `PLACEHOLDER thesis for ${seed.title}: one sentence on the idea and what it connected.`,
    clientDisplayName: "PLACEHOLDER client descriptor",
    practice: "Rapt Studio",
    location: "PLACEHOLDER location",
    years: "PLACEHOLDER",
    status: "completed",
    role: "Creative and Strategy Lead, Rapt Studio (to be confirmed)",
    scope: `${seed.kind}. PLACEHOLDER scope.`,
    team: ["Rapt Studio team"],
    collaborators: [],
    lenses: seed.lenses,
    portfolioRole: seed.kind,
    sequence: seed.sequence,
    tileSize: seed.tileSize,
    relatedProject: "intuit-turbotax-retail",
    permission: "pending",
    permissionNote: seed.note,
    heroAssetId: `${seed.id}-hero`,
  };
  const narrative: Narrative = {
    projectId: seed.id,
    summary: [
      `PLACEHOLDER: context for ${seed.title}. Two or three sentences on who the work was for and what it needed to do.`,
      "PLACEHOLDER: the idea that guided the work, and the one decision that mattered most.",
      "PLACEHOLDER: what was made, with status stated plainly.",
    ],
    challenge: [],
    insight: [],
    vision: [],
    scaleTranslation: [],
    leadership: [],
    outcome: [],
    involvement: "PLACEHOLDER: precise scope of personal involvement.",
  };
  const decisions: Decision[] = [];
  const assets: Asset[] = [
    {
      id: `${seed.id}-hero`,
      projectId: seed.id,
      file: `${seed.id}/hero.jpg`,
      type: "photo",
      caption: `PLACEHOLDER: hero image for ${seed.title}.`,
      alt: `${seed.title} hero image, to be supplied.`,
      creator: "To be confirmed",
      credit: "Credit to be confirmed",
      permission: "pending",
    },
  ];
  const claims: Claim[] = [
    {
      id: `${seed.id}-c1`,
      projectId: seed.id,
      placement: "role",
      wording: `Jamel was creative and strategy lead on ${seed.title}.`,
      evidenceSource: "fable_build_prompt.md, extended projects: confirm per project.",
      verifier: "Jamel Williams",
      status: "awaiting",
    },
  ];
  return { project, narrative, decisions, assets, claims };
}

export const extendedProjects: ProjectBundle[] = seeds.map(build);
