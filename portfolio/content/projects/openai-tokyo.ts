import type { ProjectBundle } from "../types";

const id = "openai-tokyo";

export const openaiTokyo: ProjectBundle = {
  project: {
    id,
    title: "OpenAI Tokyo",
    slug: id,
    thesis: "An interim office that harmonizes San Francisco and Tokyo into one identity, with hospitality as the organizing principle and the existing building kept.",
    clientDisplayName: "OpenAI",
    practice: "Rapt Studio",
    location: "Tokyo, Japan",
    years: "2025 to present",
    status: "in-progress",
    statusNote: "In design. Active and confidential project.",
    role: "Creative and Strategy Lead, Rapt Studio",
    scope:
      "Concept, schematic, and design development for an interim office of about 36,500 rentable square feet in an existing high-rise, bridging coworking space and a future purpose-built office, on an accelerated twelve-month schedule for about two hundred desks.",
    team: ["Rapt Studio team"],
    collaborators: ["OpenAI stakeholders in San Francisco and Tokyo"],
    lenses: ["culture-strategy", "interiors-behavior", "brand-detail"],
    portfolioRole: "Optional contrast",
    sequence: 6,
    tileSize: 2,
    homeFeature: false,
    slot: "optional",
    relatedProject: "intuit-turbotax-retail",
    permission: "pending",
    permissionNote: "Awaiting OpenAI and Rapt Studio permission. Active confidential project; a descriptive client name may be required.",
    heroAssetId: "openai-tokyo-principles",
  },
  narrative: {
    projectId: id,
    challenge: [
      "OpenAI needed a home in Tokyo for a mostly go-to-market team of about two hundred people, in an existing high-rise, for a three to five year life, on a twelve-month schedule. The office bridges a coworking arrangement and a future purpose-built space, so it had to feel permanent without being built as if it were.",
      "The harder question was cultural. Many guests meet the company as a company for the first time in this office. A one-for-one import of the San Francisco headquarters would read as a branch. A purely Japanese office would read as a different company. The judgment required was to find the identity that belonged to both cities.",
    ],
    insight: [
      "Non-verbal cues carry outsized weight in Japanese communication, and a first visit is mostly non-verbal. The architecture would speak before any words did. That made hospitality, omotenashi, the quiet art of anticipation, the natural organizing principle, and it set the bar for every surface a guest would see.",
    ],
    vision: [
      "Four principles guide the work. Harmonize the cultural energies of San Francisco and Tokyo into one identity: translate without imitating. Elevate hospitality into the guiding principle, blending omotenashi with relaxed Californian ease. Design the office as a social ecosystem built on flow and rhythm, with room for morning coffee and Friday gatherings. Let architecture speak before words, so every detail signals the company's values with a few deliberate brand moments.",
    ],
    scaleTranslation: [
      {
        lens: "culture-strategy",
        assetId: "openai-tokyo-principles",
        caption: "Culture: two cities, one identity. Four principles written down before the plan, so that each later decision could be tested against them.",
      },
      {
        lens: "interiors-behavior",
        caption: "Program: an executive briefing space, a demo space called Walk in the Park, a library, and a bar and karaoke room, arranged as a social ecosystem rather than a floor of desks with amenities attached.",
      },
      {
        lens: "brand-detail",
        caption: "Detail: subtle spatial expression carries most of the identity, with a few deliberate brand moments placed where guests pause.",
      },
    ],
    leadership: [
      "I lead creative and strategy for the project, including the principles that frame it and the decision to keep the existing architecture and spend the effort on hospitality and furniture. The Rapt team is developing the design with OpenAI's stakeholders in both cities.",
    ],
    outcome: ["In progress. No measured results to report."],
    imageCredit: "Diagram redrawn for this portfolio from the concept brief. No project imagery is shown while the project is confidential.",
    involvement: "Creative and strategy lead. Set the four principles and the reuse strategy, and directs the design through schematic and design development.",
  },
  decisions: [
    {
      id: "oait-d1",
      projectId: id,
      title: "Reuse instead of rebuild",
      question: "Where does twelve months of effort go in a space that will be left in five years?",
      choice: "Keep the existing fit-out and systems. Invest in cosmetic upgrades, furniture, and surgical construction.",
      rationale: "The schedule holds, the budget goes to the surfaces people touch, and the office avoids pretending to be permanent.",
      tradeoff: "The plan inherits constraints from the previous tenant that a full rebuild would have removed.",
      assetIds: [],
    },
    {
      id: "oait-d2",
      projectId: id,
      title: "Hospitality as the organizing principle",
      question: "What should a first-time guest understand before anyone speaks?",
      choice: "Blend omotenashi with relaxed Californian ease into a confident form of hospitality, and design the arrival and briefing sequence around it.",
      rationale: "Guests meet the company here for the first time. Anticipation is the clearest signal of care.",
      tradeoff: "Hospitality takes space and staffing that a desk-count calculation would never allocate.",
      assetIds: ["openai-tokyo-principles"],
    },
    {
      id: "oait-d3",
      projectId: id,
      title: "Atmosphere as body language",
      question: "How much brand should be visible?",
      choice: "Subtle spatial expression carries the identity, with a few deliberate brand moments.",
      rationale: "In a culture where non-verbal cues carry weight, restraint reads as confidence and a wall of logos reads as insecurity.",
      tradeoff: "The identity depends on execution quality, since there is little signage to fall back on.",
      assetIds: [],
    },
  ],
  assets: [
    {
      id: "openai-tokyo-principles",
      projectId: id,
      file: "openai-tokyo/openai-tokyo-principles-diagram.svg",
      type: "diagram",
      caption: "Two cities, one identity: the four principles that frame the Tokyo office.",
      alt: "Diagram showing San Francisco and Tokyo converging into one identity, with four principles listed beneath.",
      creator: "Portfolio diagram, redrawn from the concept brief",
      credit: "Diagram redrawn for this portfolio",
      permission: "pending",
      lens: "culture-strategy",
    },
  ],
  claims: [
    {
      id: "oait-c1",
      projectId: id,
      placement: "leadership",
      wording: "PLACEHOLDER: one moment, for example leading discovery interviews across San Francisco and Tokyo stakeholders.",
      evidenceSource: "To be supplied by Jamel.",
      verifier: "Jamel Williams",
      status: "awaiting",
    },
    {
      id: "oait-c2",
      projectId: id,
      placement: "credits",
      wording: "Team credits for the Tokyo project: PLACEHOLDER.",
      evidenceSource: "To be supplied by Jamel.",
      verifier: "Jamel Williams",
      status: "awaiting",
    },
  ],
};
