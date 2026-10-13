import type { Claim, Profile } from "./types";

// Profile copy. Sentences that describe leadership scope are stored as claims so the
// verification gate decides whether they render. PLACEHOLDER text is visible stand-in copy.
export const profile: Profile = {
  currentTitle: "Design Director, Rapt Studio",
  bio: [
    "Jamel Williams is a Design Director at Rapt Studio, where he leads creative and strategy for workplace, retail, and brand environment projects.",
    // PLACEHOLDER: add a second sentence on background and the kinds of clients served.
    "PLACEHOLDER: a sentence on background, training, and the range of clients served.",
  ],
  careerNarrative: [
    "The work moves between scales on purpose. A retail playbook for a national brand, a six-floor headquarters, a learning center inside a data center, and a single store for a running community each ask the same questions in a different order: what gives this work meaning, how does the idea shape a place, what should people feel and do there, and where does identity become recognizable.",
    "Working across strategy, architecture, interiors, and brand has shaped a particular kind of judgment. It is easier to tell when a detail is carrying a strategy, and when a strategy is about to lose its detail. That is the judgment a creative director is paid for, and it is what this portfolio sets out to show.",
    // PLACEHOLDER: add a paragraph on formative experience and how it shaped the practice.
    "PLACEHOLDER: a paragraph on formative experience and how it shaped the practice.",
  ],
  workingStyle: [
    "Establish the idea early and write down the criteria for judging decisions against it.",
    "Critique the work, credit the people, and resolve competing priorities in the room.",
    "Stay close to delivery so the intent survives value engineering and schedule.",
  ],
  leadershipClaimIds: ["profile-lead-01", "profile-lead-02", "profile-lead-03"],
  experience: [
    { period: "Current", title: "Design Director", organisation: "Rapt Studio", note: "Creative and strategy lead across workplace, retail, and brand environments." },
    // PLACEHOLDER: add prior roles in reverse chronological order.
    { period: "PLACEHOLDER", title: "PLACEHOLDER role", organisation: "PLACEHOLDER organisation" },
  ],
  credentials: [
    // PLACEHOLDER: degrees, licences, awards, talks, publications.
    "PLACEHOLDER: education and credentials",
  ],
  cvReference: "/cv.pdf",
};

export const profileClaims: Claim[] = [
  {
    id: "profile-lead-01",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "Creative and strategy lead on the projects shown here, confirmed by Jamel on 13 October 2026.",
    evidenceSource: "portfolio_research.md, note at top: Jamel confirmed creative and strategy lead on all ten projects.",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "profile-lead-02",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "PLACEHOLDER: team size and the number of concurrent projects typically directed.",
    evidenceSource: "To be supplied by Jamel.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
  {
    id: "profile-lead-03",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "PLACEHOLDER: responsibilities beyond project work, for example hiring, mentoring, or studio practice development.",
    evidenceSource: "To be supplied by Jamel.",
    verifier: "Jamel Williams",
    status: "awaiting",
  },
];
