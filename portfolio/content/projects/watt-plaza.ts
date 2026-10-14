import type { ProjectBundle } from "../types";

const id = "watt-plaza";

export const wattPlaza: ProjectBundle = {
  project: {
    id,
    title: "Watt Plaza",
    slug: id,
    thesis: "Making early design choices visible.",
    clientDisplayName: "Family-owned commercial office owner, Century City",
    practice: "Rapt Studio",
    location: "Century City, Los Angeles, California",
    years: "2025 to present",
    status: "concept",
    statusNote: "Unbuilt, AI-assisted concept. Direction being synthesized.",
    role: "Creative and strategy lead; author and operator of the AI workflow",
    scope:
      "Building repositioning study for twin office towers, plaza, and parking structure: a competitive survey, three directions pushed to their boundary condition, and a sketch-to-render pipeline that produced facade, base, landscape, and night views between two owner reviews.",
    team: ["Rapt Studio: Jamel Williams with Ben K, Ruth M, and Ashley C"],
    collaborators: [],
    lenses: ["culture-strategy", "architecture-place", "brand-detail"],
    tier: "core",
    caseStudy: "full",
    inPdf: true,
    landingTile: true,
    tiles: [{ x: 71, y: 4, depth: 3, order: 2 }],
    portfolioRole: "Process and possibility",
    sequence: 8,
    tileSize: 2,
    relatedProject: "intuit-turbotax-retail",
    permission: "confirmed",
    permissionNote: "Awaiting client and Rapt Studio sign-off. Pricing tiers, attendee names, and the neighboring building are excluded from all copy.",
    heroAssetId: "watt-postures",
  },
  narrative: {
    projectId: id,
    summary: [
      "Watt Plaza explores alternative directions for repositioning an existing building. AI-assisted visualization helped make the differences between those directions tangible enough to discuss before committing to detailed development.",
      "I led the visual direction and AI workflow, defining references, evaluating outputs, and incorporating design feedback. Strategy, plans, and parts of the imagery were developed collaboratively within the studio.",
      "The work remains an unbuilt concept. Its value in this portfolio is the relationship between exploration and judgment: how alternatives were presented, critiqued, and refined into a clearer direction.",
    ],
    challenge: [
      "Watt Plaza started as a focused landscape and ground-floor refresh. After the spring concept rounds the owners came back with a bigger request: a building that reads as a destination. The scope moved from the plaza to the whole building, facade, landscape, amenities, program, and identity, in a matter of weeks.",
            "That created a production problem. A building-scale repositioning needs facade, bridge, retail base, landscape, and night views for several competing ideas, and the owners needed to compare them before committing fees to detailed development of any one.",
    ],
    insight: [
      "The strategy came first. A survey of twelve Century City buildings sorted their amenities into table stakes, common, and rare, and found that no competitor had built a repositioning around one coherent posture toward the neighborhood. That gave three directions, each answering a gap: Departure, where the building faces out with a public market and shared roof garden; Extension, where it faces in with a members' club on an amenity bridge and a top-of-building restaurant; and Expansion, which meets the city halfway with a raised open-air promenade.",
      "The creative move was to show each direction at its extreme. We designed to the boundary condition first because it sharpens the choice. A refinish-only option marked the other pole, and every later decision would tune between the two.",
    ],
    vision: [
      "Designing to the boundary only works if the extremes are vivid and believable. The AI pipeline made that affordable. Every image answered to three kinds of authority: geometry from whitecard massing and the existing site plan, material from curated references, and intent from my redlines and written direction. A prompt-writing agent, framed as a professional architectural visualizer who takes direction from the creative director, turned intent into image-model prompts. Edits stayed scoped, and the best results were composited at the end.",
    ],
    scaleTranslation: [
      {
        lens: "culture-strategy",
        assetId: "watt-postures",
        caption: "Strategy: twelve buildings, three gaps, three postures. Each direction answers a gap the survey found.",
      },
      {
        lens: "architecture-place",
        assetId: "watt-pipeline",
        caption: "Place: one accurate base plate of the existing towers, then every direction edited from it, so the comparison is fair because only the design changes.",
      },
      {
        lens: "brand-detail",
        caption: "Detail: a hand-drawn facade gradient in thirds, solid at the base and open at the top, became the Extension hero in one working day, with a green-stone retail base from ground-floor redlines and terraced landscape slabs from the spring sketches.",
      },
      {
        lens: "architecture-place",
        caption: "Feedback in, a new boundary out: after the first review, the Expansion direction became a fully glass box with limited site changes, and a reduced-scope page added three lighter options.",
      },
    ],
    leadership: [
      "I led the visual direction and the AI method: the reference roles, the two-agent prompt chain, the scoped edits, and the curation, redlines, and design intent behind the Extension and Expansion renders. The deck's strategy, survey, plans, and Departure imagery were shared studio work, and the shift of the third direction to a glass box came from a teammate's review.",
    ],
    leadershipMoment:
      "In the two weeks between the two owner reviews, client feedback went straight back into the pipeline. That produced the glass-box Expansion, the alternate materials, and the reduced-scope options without starting over.",
    outcome: [
      "The boundary renders gave the owners something concrete to react to, and their reactions became design decisions. Leadership rejected the skybridge in one meeting and kept the moves that worked across all three directions: a relocated valet, retail on the first floor with amenity above, and reclad fins with new glazing. The next step is one synthesized direction with cost tiers from refinish-only to full intervention. Unbuilt, and labeled as AI-assisted concept work.",
    ],
    reflection:
      "Speed alone did not change the conversation. The renders did, because they made each extreme real enough to reject. The owners could say no to a skybridge in one meeting and yes to a relocated valet, and the design got clearer from both.",
    imageCredit: "Diagrams redrawn for this portfolio. Pipeline renders are AI-assisted concept images produced in Weave with Gemini image models under Jamel's direction, to be exported and added once cleared.",
    involvement:
      "Creative and strategy lead, and author and operator of the AI workflow. Directed the Extension and Expansion directions and the method that produced them.",
  },
  decisions: [
    {
      id: "watt-d1",
      projectId: id,
      title: "Show the extremes first",
      question: "How do you help owners choose an ambition level they cannot yet picture?",
      choice: "Render each posture at its boundary, alongside a refinish-only pole, and let the owners set the intensity.",
      rationale: "Clear extremes sharpen the choice and show how far each posture can go before deciding how far it should.",
      tradeoff: "The owners react to the most radical version of each idea, so some reactions are to the extreme rather than to the idea.",
      assetIds: ["watt-postures"],
    },
    {
      id: "watt-d2",
      projectId: id,
      title: "Lock the base plate before designing",
      question: "How do generative renders stay honest to an existing building?",
      choice: "Build an accurate photoreal plate from whitecard geometry first, and edit every direction from it.",
      rationale: "The comparison between directions is fair because only the design changes.",
      tradeoff: "A slower first day, and deliberately flat lighting.",
      assetIds: ["watt-pipeline"],
    },
    {
      id: "watt-d3",
      projectId: id,
      title: "Draw the intent and let an agent write the prompt",
      question: "How does design judgment survive translation into prompts?",
      choice:
        "Direction travels through redlines and plain-language intent. A dedicated visualizer agent writes the prompts, and every edit is scoped to one part of the building.",
      rationale: "The designer stays in the language of design, and each decision stays separable and reviewable.",
      tradeoff: "Many candidate images per decision, and curating them takes judgment.",
      assetIds: ["watt-pipeline"],
    },
  ],
  assets: [
    {
      id: "watt-postures",
      projectId: id,
      file: "watt-plaza/watt-three-postures-diagram.svg",
      type: "diagram",
      caption: "Three postures toward the neighborhood: Departure faces out, Extension faces in, Expansion meets the city halfway. A refinish-only option marks the other pole.",
      alt: "Diagram of three building postures labeled Departure, Extension, and Expansion, with a refinish-only pole at one end.",
      creator: "Portfolio diagram, redrawn from the concept deck",
      credit: "Diagram redrawn for this portfolio",
      permission: "confirmed",
      lens: "culture-strategy",
    },
    {
      id: "watt-pipeline",
      projectId: id,
      file: "watt-plaza/watt-pipeline-diagram.svg",
      type: "diagram",
      caption: "The pipeline: geometry, material, and intent feed a prompt-writing agent, which drives the image model. Scoped edits and a final composite follow.",
      alt: "Flow diagram from three inputs, geometry, material, and intent, through a prompt agent and image model to scoped edits and a composite.",
      creator: "Portfolio diagram, redrawn from the Weave flow",
      credit: "Diagram redrawn for this portfolio",
      permission: "confirmed",
      lens: "architecture-place",
    },
  ],
  claims: [
    {
      id: "watt-c1",
      projectId: id,
      placement: "context",
      wording: "About 195 image generations and 110 prompt-writing runs, from the node run counters in the flow.",
      evidenceSource: "watt_plaza_ai_case_study.md, At a glance; Appendix A.",
      verifier: "Jamel Williams",
      status: "omit",
    },
    {
      id: "watt-c2",
      projectId: id,
      placement: "credits",
      wording: "Authorship across the two Weave accounts in the flow, and the author of the Departure imagery: PLACEHOLDER.",
      evidenceSource: "watt_plaza_ai_case_study.md, open items 2 and 3.",
      verifier: "Jamel Williams",
      status: "awaiting",
    },
    {
      id: "watt-c3",
      projectId: id,
      placement: "role",
      wording: "Author and operator of the AI workflow, including the revisions produced between the two reviews.",
      evidenceSource: "watt_plaza_ai_case_study.md, Section 9.",
      verifier: "Jamel Williams",
      status: "awaiting",
    },
  ],
};
