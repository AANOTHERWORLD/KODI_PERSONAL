import type { ApproachExample, ApproachStep } from "./types";

export const approachSteps: ApproachStep[] = [
  {
    id: "read-the-context",
    number: 1,
    title: "Read the Context",
    summary: "Understand people, culture, client ambition, and constraints before defining form.",
  },
  {
    id: "define-the-direction",
    number: 2,
    title: "Define the Direction",
    summary: "Establish a clear idea and decision criteria strong enough to guide or reject options.",
  },
  {
    id: "connect-the-scales",
    number: 3,
    title: "Connect the Scales",
    summary: "Translate the idea across architecture, interior environments, brand, behavior, and detail.",
  },
  {
    id: "guide-the-team",
    number: 4,
    title: "Guide the Team",
    summary: "Build shared understanding and empower multidisciplinary specialists to contribute coherently.",
  },
  {
    id: "protect-the-intent",
    number: 5,
    title: "Protect the Intent",
    summary: "Navigate delivery pressures without losing the defining creative idea.",
  },
];

export const approachHeading = "Creative Direction as a Practice";
export const approachIntro = [
  "Strong creative leadership requires more than a compelling initial idea. It requires the ability to establish a shared direction, build alignment across disciplines, and guide teams through the competing demands of design, delivery, and business.",
  "My approach is built around five interconnected practices. Together, they help transform complex ambitions into clear creative ideas, empower teams to make meaningful decisions, and protect design excellence from concept through completion.",
  "The goal is not to create the same outcome repeatedly, but to establish a consistent standard of creative thinking across different people, projects, and scales.",
];
// Short statements shown under a step, keyed by step id.
export const approachStatements: Record<string, string> = {
  "guide-the-team": "Creative leadership is not about making every decision. It is about giving people the shared understanding, confidence, and responsibility to make good decisions together.",
  "protect-the-intent": "The measure of a strong design direction is not how closely the final result resembles its first sketch, but how successfully its defining idea survives budget, schedule, technical coordination, and change.",
};

export const approachAi = {
  heading: "AI and design judgment",
  body: "I use AI-assisted visualization to explore alternatives and make early choices easier to discuss. The value lies in the design judgment around it: defining the question, selecting references, evaluating outputs, and translating promising directions into work the team can test and develop.",
  projectId: "watt-plaza",
};

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
    example: "Relief became the ownable emotional territory for TurboTax retail, with six imperatives, from designing the system rather than the store to signaling permanence, as the criteria for every store decision.",
  },
  {
    step: "define-the-direction",
    projectId: "watt-plaza",
    example: "When the Watt Plaza brief grew from a plaza to a whole building, three futures with different positions let the client compare how much change each one required.",
  },
  {
    step: "connect-the-scales",
    projectId: "tinder-hq",
    example: "Human connection as a gradient shaped the stacking of floors, the geometry of a library table, and a prize wall of company easter eggs.",
  },
  {
    step: "connect-the-scales",
    projectId: "lsd-running",
    example: "Three brand pillars, curation, craft and expertise, and transparency, were carried from the mark into the store and the way it was photographed.",
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
    example: "When the workforce became distributed in 2020, the floors were re-tested against how teams actually worked, and the plan changed without losing the connection spaces.",
  },
  {
    step: "protect-the-intent",
    projectId: "openai",
    example: "In Tokyo, retaining much of the existing fit-out focused the design effort on hospitality, furniture and targeted changes within an accelerated schedule.",
  },
];
