import type { Asset, Claim, Profile } from "./types";

// Profile copy. Recognition and leadership facts are claims so the verification gate decides
// whether they render. PLACEHOLDER text is visible stand-in copy.
export const profile: Profile = {
  name: "Jamel Williams",
  currentTitle: "Design Director, Rapt Studio",
  bio: "I trained as an architect and moved into brand and creative strategy, working with cross-disciplinary teams across many industries. I bring spatial rigor, creative range, and collaborative fluency to every project.",
  aboutStatement: "Design Director who sets one direction and carries it across place, brand, and the details people touch.",
  careerNarrative: [
    "The work moves between scales on purpose. A retail playbook for a national brand, a six-floor headquarters, a learning center inside a data center, and a single store for a running community each ask the same questions in a different order: what gives this work meaning, how does the idea shape a place, what should people feel and do there, and where does identity become recognizable.",
    "Architecture taught me to hold a plan, a section, and a detail in my head at the same time. Brand and strategy work taught me to hold an audience there too. Working across both has shaped a particular kind of judgment: it is easier to tell when a detail is carrying a strategy, and when a strategy is about to lose its detail.",
    // PLACEHOLDER: add a paragraph on formative experience and how it shaped the practice.
    "PLACEHOLDER: a paragraph on formative experience and how it shaped the practice.",
  ],
  workingStyle: [
    "Establish the idea early and write down the criteria for judging decisions against it.",
    "Critique the work, credit the people, and resolve competing priorities in the room.",
    "Stay close to delivery so the intent survives value engineering and schedule.",
  ],
  experience: [
    { title: "Design Director", practice: "Rapt Studio", years: "2024 to present" },
    { title: "Senior Designer", practice: "Rapt Studio", years: "2017 to 2024" },
    { title: "Associate Architect", practice: "Collective Architecture", years: "2010 to 2017" },
  ],
  recognitionClaimIds: ["rec-01", "rec-02", "rec-03", "rec-04", "rec-05"],
  leadershipClaimIds: ["profile-lead-01", "profile-lead-02", "profile-lead-03"],
  credentials: [
    // PLACEHOLDER: degrees, licences, talks, publications.
    "PLACEHOLDER: education and credentials",
  ],
  portraitAssetId: "profile-portrait",
  cvReference: "/cv.pdf",
};

// The full-bleed portrait on Home. Self-portrait by Jamel, permission confirmed.
export const profileAssets: Asset[] = [
  {
    id: "profile-portrait",
    projectId: "profile",
    file: "profile/portrait.jpg",
    type: "photo",
    caption: "Jamel Williams.",
    alt: "Jamel Williams seated on a wooden chair with legs crossed, in a black sweater and olive trousers, against a draped rust backdrop.",
    creator: "Jamel Williams",
    credit: "Photography: Jamel Williams",
    permission: "confirmed",
  },
];

export const profileClaims: Claim[] = [
  {
    id: "rec-01",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "Interior Design Magazine, cover feature",
    evidenceSource: "Webflow prototype, Recognition Highlights. Project to be confirmed.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
  {
    id: "rec-02",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "FX Awards, Mixed Use Development finalist",
    evidenceSource: "Webflow prototype, Recognition Highlights. Project to be confirmed.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
  {
    id: "rec-03",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "World Interiors News Awards, Co-Working Spaces finalist",
    evidenceSource: "Webflow prototype, Recognition Highlights. Project to be confirmed.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
  {
    id: "rec-04",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "World Interiors News Awards, Silver Winner, Workplace Interiors over 10,000 sqm",
    evidenceSource: "Webflow prototype, Recognition Highlights. Project to be confirmed.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
  {
    id: "rec-05",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "FRAME, feature on Tinder's new HQ: How Can Offices be the Perfect Match for Employee Connection?",
    evidenceSource: "Webflow prototype, Recognition Highlights.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
  {
    id: "profile-lead-01",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "Creative and strategy lead on every project shown here, confirmed by Jamel on 13 October 2026.",
    evidenceSource: "portfolio_research.md and portfolio_brief.md, Section 5.",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "profile-lead-02",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "Leads a team of about eleven across disciplines on roughly seven concurrent projects.",
    evidenceSource: "portfolio_brief.md, Section 9: candidate fact to reconfirm before publication.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
  {
    id: "profile-lead-03",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "Responsible for business development and staffing on the studio's Los Angeles projects. This describes scope, never performance.",
    evidenceSource: "portfolio_brief.md, Section 9: candidate fact to reconfirm before publication.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
];
