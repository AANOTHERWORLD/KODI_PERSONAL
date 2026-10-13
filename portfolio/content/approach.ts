import type { ApproachExample, ApproachStep } from "./types";

export const approachSteps: ApproachStep[] = [
  {
    id: "read-the-context",
    number: 1,
    title: "Read the context",
    summary: "Understand culture, audience, place, and ambition before proposing anything. The brief is a starting point. The real problem usually sits one level beneath it.",
  },
  {
    id: "define-the-direction",
    number: 2,
    title: "Define the direction",
    summary: "Establish one idea and the criteria for judging decisions against it. A direction that cannot say no to something is a mood, and a mood cannot lead a team.",
  },
  {
    id: "connect-the-scales",
    number: 3,
    title: "Connect the scales",
    summary: "Translate the idea across disciplines and touchpoints, from site and plan to seating angle and signage, so each scale can be read as the same decision.",
  },
  {
    id: "guide-the-team",
    number: 4,
    title: "Guide the team",
    summary: "Create alignment, critique constructively, and resolve competing priorities. Shared vocabulary and visible criteria let the team make decisions without waiting for a director.",
  },
  {
    id: "protect-the-intent",
    number: 5,
    title: "Protect the intent",
    summary: "Adapt to budget, schedule, and client feedback while preserving what matters. Some moves are negotiable. The ones that carry the idea are named early and defended.",
  },
];

export const approachExamples: ApproachExample[] = [
  {
    step: "read-the-context",
    projectId: "google-gso-home-of-the-internet",
    example: "A request for a recruiting campaign became a community platform once discovery showed that data center work was invisible to the towns that host it.",
  },
  {
    step: "read-the-context",
    projectId: "tinder-hq",
    example: "Five interview sessions, nine stakeholders, and eight team swarms established what culture meant for Tinder before any plan was drawn.",
  },
  {
    step: "define-the-direction",
    projectId: "intuit-turbotax-retail",
    example: "Relief became the ownable emotional territory for TurboTax retail, with four imperatives, Privacy, Proximity, Peak, and Permanence, as the criteria for every store decision.",
  },
  {
    step: "define-the-direction",
    projectId: "watt-plaza",
    example: "Three building postures were pushed to their boundary condition first, so the owners could choose an ambition level before anyone paid for precision.",
  },
  {
    step: "connect-the-scales",
    projectId: "tinder-hq",
    example: "Human connection as a gradient shaped the stacking of floors, the geometry of a library table, and a prize wall of company easter eggs.",
  },
  {
    step: "connect-the-scales",
    projectId: "lsd-running",
    example: "Three brand pillars, craft, curation, and innovation, became a plan with concealed storage, a bench that doubles as seating, and a wall made from the brand's own ripstop nylon.",
  },
  {
    step: "guide-the-team",
    projectId: "intuit-turbotax-retail",
    example: "A naming crosswalk retired legacy terminology before the first client presentation, so every Intuit team discussed the same stores, tiers, and environments.",
  },
  {
    step: "guide-the-team",
    projectId: "lsd-running",
    example: "Five schemes developed through studio swarms were synthesized into one design rather than reduced to a winner.",
  },
  {
    step: "protect-the-intent",
    projectId: "tinder-hq",
    example: "When the workforce became distributed in 2020, six new space typologies were tested and force-ranked against team working styles, and density was reduced without losing the connection spaces.",
  },
  {
    step: "protect-the-intent",
    projectId: "openai-tokyo",
    example: "A twelve-month schedule in an existing high-rise was met by keeping the architecture and systems, and spending the design effort on hospitality, furniture, and a few deliberate brand moments.",
  },
];
