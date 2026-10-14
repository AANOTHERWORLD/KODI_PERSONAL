import type { ApproachExample, ApproachStep } from "./types";

export const approachSteps: ApproachStep[] = [
  {
    id: "read-the-context",
    number: 1,
    title: "Understand the context",
    summary: "Start with the people, place, and ambition. Listen for the needs behind the brief and identify the tension the design must resolve.",
  },
  {
    id: "define-the-direction",
    number: 2,
    title: "Establish the direction",
    summary: "Define an idea the client and team can use. Translate it into clear criteria for evaluating concepts, communicating choices, and deciding what matters most.",
  },
  {
    id: "connect-the-scales",
    number: 3,
    title: "Connect the scales",
    summary: "Test the direction in the plan, the experience, the material, and the detail. Let discoveries at each scale improve the others.",
  },
  {
    id: "guide-the-team",
    number: 4,
    title: "Guide the collaboration",
    summary: "Create room for different disciplines to contribute. Use reviews to clarify choices, develop the work, and resolve competing priorities around a shared intent.",
  },
  {
    id: "protect-the-intent",
    number: 5,
    title: "Carry the idea through",
    summary: "Adapt to changing needs, budgets, and delivery constraints. Identify the decisions that carry the idea and maintain their continuity as the project develops.",
  },
];

export const approachHeading = "A shared direction. A deliberate process.";
export const approachIntro =
  "Every project asks for a different response. My process creates continuity between understanding the brief, defining an idea, and making the decisions that bring it to life.";

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
    example: "When the workforce became distributed in 2020, the floors were re-tested against how teams actually worked, and the plan changed without losing the connection spaces.",
  },
  {
    step: "protect-the-intent",
    projectId: "openai-tokyo",
    example: "A twelve-month schedule in an existing high-rise was met by keeping the architecture and systems, and spending the design effort on hospitality, furniture, and a few deliberate brand moments.",
  },
];
