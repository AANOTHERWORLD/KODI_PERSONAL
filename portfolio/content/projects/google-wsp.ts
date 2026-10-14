import type { ProjectBundle } from "../types";

const id = "google-wsp";

// Extended project (website only), light page with a captioned gallery.
export const googleWsp: ProjectBundle = {
  project: {
    id,
    title: "Google WSP Campus",
    slug: id,
    thesis: "Intimacy at scale across a 540,000 square foot campus.",
    clientDisplayName: "Google",
    practice: "Rapt Studio",
    location: "Los Angeles, California",
    years: "2020 to 2021",
    status: "concept",
    statusNote: "Unbuilt. Google changed direction during the pandemic and the project wrapped in 2021.",
    role: "Senior Designer, Rapt Studio, working directly with the creative director and account lead",
    scope: "Workplace concept and planning strategy for the adaptive reuse of the Westside Pavilion into a Google campus: integrated team neighborhoods, a planning framework and indoor and outdoor amenity spaces.",
    team: ["Rapt Studio team"],
    collaborators: ["Google Real Estate and Workplace Services", "ZGF Architects", "SWA Landscape Architecture"],
    lenses: ["culture-strategy", "architecture-place", "interiors-behavior"],
    tier: "core",
    caseStudy: "light",
    inPdf: false,
    landingTile: true,
    tiles: [{ x: 48, y: 52, depth: 2, order: 17 }],
    portfolioRole: "Scale and flexibility",
    typeLabel: "Workplace campus",
    disciplines: "Workplace strategy, Planning, Interiors",
    sequence: 17,
    tileSize: 3,
    relatedProject: "google-room-98",
    permission: "confirmed",
    permissionNote: "Design development imagery from the 2020 WSP design updates. Footers and page furniture are cropped out.",
    heroAssetId: "wsp-axon",
    indexAssetId: "wsp-rideshare",
  },
  narrative: {
    projectId: id,
    summary: [
      "Google's WSP campus in Los Angeles is a 540,000 square foot adaptive reuse of the Westside Pavilion. The design had to make a very large floor plate feel like a place where teams belong, and stay flexible for the long term.",
      "I worked directly with the creative director and account lead, alongside Google's real estate and workplace team, ZGF Architects and SWA Landscape Architecture, to develop concepts and design strategy, from early development through delivery and execution.",
    ],
    challenge: [
      "The brief was to transform a 540,000 square foot adaptive reuse project into a design built for long-horizon flexibility. Scale was the risk. A floor plate that large can feel anonymous, and the way teams work will keep changing over the life of the building.",
    ],
    insight: [
      "Organizational ambiguity needed a structure, and the structure needed to feel human. Intimacy at scale became the idea: smaller, recognizable places inside a very large building.",
    ],
    vision: [
      "Integrated Team Neighborhoods break the campus into rotating 40-person modules. Each gives a team a home base and a sense of belonging, and each can evolve its components as the team's work style changes over time.",
      "The design narrative describes a workplace that is approachable, connected, authentic to Los Angeles, welcoming and adaptable, an interior that acts as a refuge from the exterior. Google's own design principles, from a baseline of basic infrastructure up to innovative and replicable solutions, framed the work.",
      "Four planning concepts organized the campus. Public and secure space gives distinct zones both freedom and security. A focus and activity model consolidates activity on a middle floor, which protects focus space and encourages serendipitous run-ins. Meaningful outdoors ensures that outdoor areas work for work, fitness and food. Flexibility and modularity let decisions at the block plan level keep workspace flexible.",
    ],
    scaleTranslation: [
      { lens: "culture-strategy", assetId: "wsp-narrative", caption: "Strategy: a design narrative built on approachable, connected, authentic, welcoming and adaptable." },
      { lens: "architecture-place", assetId: "wsp-planning", caption: "Place: four planning concepts, public and secure space, a focus and activity model, meaningful outdoors, and flexibility." },
      { lens: "interiors-behavior", assetId: "wsp-axon", caption: "Behavior: team neighborhoods drawn across the floor plate, each a home base inside a very large building." },
    ],
    leadership: [
      "As senior designer, I worked directly with the creative director and account lead to develop concepts and design strategy, from early development through delivery and execution. The Rapt team developed the neighborhood planning and the amenity spaces with Google and the architecture and landscape partners.",
    ],
    outcome: [
      "The campus was not built. Google changed direction during the pandemic and the project wrapped in 2021. The images show design development studies and concept views, and document the planning approach.",
    ],
    involvement: "Senior Designer. Worked directly with the creative director and account lead on concepts and design strategy, from early development to delivery.",
  },
  decisions: [
    {
      id: "wsp-d1",
      projectId: id,
      title: "Answer scale with neighborhoods",
      question: "How does a 540,000 square foot campus feel like a place to belong?",
      choice: "Organize workspace into rotating 40-person Integrated Team Neighborhoods, each with its own home base.",
      rationale: "Smaller modules give teams immediate options, a home and belonging on a busy site, and let components change as work styles change.",
      tradeoff: "A modular kit needs clear rules so that neighborhoods can evolve without losing the shared language.",
      assetIds: ["wsp-axon"],
    },
    {
      id: "wsp-d2",
      projectId: id,
      title: "Separate public from secure, and consolidate activity",
      question: "How does the plan protect focus while keeping people connected?",
      choice: "Zone public and secure space distinctly, and consolidate activity on a middle floor.",
      rationale: "Distinct zones afford freedom and security, and a central activity floor protects focus space while encouraging serendipitous run-ins.",
      tradeoff: "Concentrating activity on one floor asks teams on other floors to travel for it.",
      assetIds: ["wsp-planning"],
    },
  ],
  assets: [
    { id: "wsp-axon", projectId: id, file: "google-wsp/wsp-team-neighborhood-axon.jpg", type: "concept", caption: "Team neighborhoods in a drawn axonometric, the same logic applied across the campus floor plate.", alt: "Hand-drawn axonometric of an open office floor with furniture, enclosed rooms and a central circulation spine.", creator: "Rapt Studio", credit: "Concept sketch, Rapt Studio", permission: "confirmed", lens: "interiors-behavior" },
    { id: "wsp-rideshare", projectId: id, file: "google-wsp/wsp-rideshare-drop-off.jpg", type: "concept", caption: "Rideshare drop-off approach: a landscaped, colorful courtyard in front of a living green wall.", alt: "Concept view of a courtyard with a patterned, brightly colored paving, people walking, and a building with a green wall.", creator: "Rapt Studio and project team", credit: "Concept view, Rapt Studio with project partners", permission: "confirmed", lens: "architecture-place" },
    { id: "wsp-planning", projectId: id, file: "google-wsp/wsp-planning-concepts.jpg", type: "diagram", caption: "Planning concepts: public and secure space, focus and activity, meaningful outdoors, flexibility and modularity.", alt: "Four isometric diagrams labeled Public/Secure Space, Focus/Activity Model, Meaningful Outdoors and Flexibility/Modularity.", creator: "Rapt Studio", credit: "Diagram, Rapt Studio", permission: "confirmed", lens: "architecture-place" },
    { id: "wsp-narrative", projectId: id, file: "google-wsp/wsp-design-narrative.jpg", type: "diagram", caption: "Design narrative: approachable, connected, authentic, welcoming and adaptable.", alt: "Diagram of the building at the center of words describing the design narrative, such as approachable, connected, welcoming and adaptable.", creator: "Rapt Studio", credit: "Diagram, Rapt Studio", permission: "confirmed", lens: "culture-strategy" },
    { id: "wsp-anchor-cafe", projectId: id, file: "google-wsp/wsp-anchor-cafe-food-hall.jpg", type: "concept", caption: "Anchor cafe and food hall, indoor and outdoor, with meeting points and diverse seating typologies.", alt: "Axonometric view of an indoor and outdoor food hall with stepped seating and inset vignettes of seating types.", creator: "Rapt Studio", credit: "Concept view, Rapt Studio", permission: "confirmed", lens: "interiors-behavior" },
    { id: "wsp-building", projectId: id, file: "google-wsp/wsp-building-overview.jpg", type: "diagram", caption: "Building overview: the mall building and the Nordstrom building, with their exterior landscape.", alt: "Line diagram of two connected buildings with labels for the mall building, the Nordstrom building and surrounding streets.", creator: "Rapt Studio", credit: "Diagram, Rapt Studio", permission: "confirmed", lens: "architecture-place" },
    { id: "wsp-principles", projectId: id, file: "google-wsp/wsp-google-design-principles.jpg", type: "diagram", caption: "Google's design principles, from a baseline of workplace infrastructure up to innovative and replicable solutions.", alt: "Pyramid of seven colored tiers, from Baseline at the bottom to Innovative and Replicable at the top.", creator: "Google", credit: "Framework, Google. Used to frame the campus design", permission: "confirmed", lens: "culture-strategy" },
  ],
  claims: [
    {
      id: "wsp-c1",
      projectId: id,
      placement: "role",
      wording: "Senior Designer on the Google WSP campus, working directly with the creative director and account lead.",
      evidenceSource: "Confirmed by Jamel Williams, October 14, 2026.",
      verifier: "Jamel Williams",
      status: "verified",
    },
  ],
};
