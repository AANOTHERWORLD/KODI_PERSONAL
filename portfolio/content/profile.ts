import type { Asset, Claim, Profile } from "./types";

// Profile copy. Recognition and leadership facts are claims so the verification gate decides
// whether they render. PLACEHOLDER text is visible stand-in copy.
export const profile: Profile = {
  name: "Jamel Williams",
  currentTitle: "Design Director, Rapt Studio",
  bio: "I am Jamel Williams, a Design Director at Rapt Studio with a background in architecture and a practice spanning interiors, brand, and creative strategy. I bring these disciplines together to set direction, guide collaboration, and keep the central idea present through design and delivery.",
  aboutStatement: "Creative direction, from the larger idea to the individual experience.",
  leadershipStatement: "Direction that a team can build on.",
  leadershipSummary:
    "My role is to make the ambition clear, give the team useful criteria, and help resolve the decisions that shape the work. I lead through shared language, constructive critique, and close attention to how the idea becomes a real experience.",
  aboutIntro: [
    "I am a multidisciplinary design leader working at the intersection of architecture, interiors, brand, and experience.",
    "Over more than 15 years, my practice has evolved from architectural design into creative leadership, shaped by the belief that the most meaningful environments emerge when strategic intent and physical experience are considered together.",
    "As Design Director at Rapt Studio, I lead a multidisciplinary team of approximately 11 designers across seven concurrent projects. My responsibilities span creative direction, client relationships, project profitability, and contributions to business development and staffing.",
    "I believe the role of creative leadership is to establish a clear vision, create the conditions for talented people to do their best work, and ensure that the original idea remains meaningful as it moves through different disciplines, scales, and complexities.",
    "My work spans workplace environments, retail concepts, branded experiences, and cultural and community-focused initiatives. Across each, my focus is consistent: connecting people, place, and purpose through thoughtful, ambitious design.",
  ],
  leadershipSnapshot: [
    "15+ years in architecture, interiors, and experience-led design",
    "11 multidisciplinary team members under current leadership",
    "7 concurrent projects under current oversight",
    "Project-level profitability accountability",
    "Business development and staffing participation",
  ],
  careerNarrative: [
    "I am Jamel Williams, a Design Director at Rapt Studio. My background in architecture informs a practice that spans interiors, brand, and creative strategy. I work across these disciplines because a place is experienced as a whole: its story, spatial organization, material character, and smallest interactions shape one another.",
    "Architecture taught me to move between the whole and the detail. Brand and strategy expanded that view to include the people a project needs to reach and the meaning it should carry. Together, they shape how I establish direction and judge whether a design decision serves the larger idea.",
  ],
  leadershipNarrative: [
    "I establish a clear idea early, then work with the team to translate it into decisions. My contribution moves between framing the brief, guiding concepts, discussing choices with clients, and maintaining continuity as the design develops.",
    "I value critique that explains why a choice matters. Shared criteria give collaborators room to contribute and make it easier to resolve competing priorities. The aim is a coherent result that benefits from the strengths of the people making it.",
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
  // Degrees, institutions, and registration (with jurisdiction and status) go here once
  // confirmed. The section stays hidden while the list is empty.
  credentials: [],
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
    wording: "Tinder HQ: Interior Design, April 2023 cover feature",
    evidenceSource: "Publisher or official results page, checked October 2026. Project and studio recognition, not an individual award.",
    url: "https://issuu.com/interiordesignmagazine/docs/id_2023_april",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "rec-02",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "Tinder HQ: WIN Awards 2023, silver, corporate offices over 10,000 sqm",
    evidenceSource: "Publisher or official results page, checked October 2026. Project and studio recognition, not an individual award.",
    url: "https://www.worldinteriorsnewsawards.com/2023-Results",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "rec-03",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "Tinder HQ: FRAME, editorial feature on employee connection",
    evidenceSource: "Publisher or official results page, checked October 2026. Project and studio recognition, not an individual award.",
    url: "https://frameweb.com/article/work/tinder-hq-west-hollywood-rapt-studio-employee-connection",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "rec-04",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "The Mark: FX Awards 2022, finalist, mixed-use development",
    evidenceSource: "Publisher or official results page, checked October 2026. Project and studio recognition, not an individual award.",
    url: "https://raptstudio.com/work/5670-wilshire/",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "rec-05",
    projectId: "profile",
    placement: "profile-recognition",
    wording: "The Mark: WIN Awards 2022, finalist, co-working spaces",
    evidenceSource: "Publisher or official results page, checked October 2026. Project and studio recognition, not an individual award.",
    url: "https://www.worldinteriorsnewsawards.com/finalists/5670-wilshire-boulevard-w0004",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "profile-lead-01",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "I was the only design director on Intuit and OpenAI. On the other Design Director projects I led the design with the internal Rapt team. On Room 98, Tokyo, Tinder, The Mark and April Jean I worked as a senior designer, directly with the creative director and account lead, from early development to delivery.",
    evidenceSource: "portfolio_research.md and portfolio_brief.md, Section 5.",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "profile-lead-02",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "Leads a team of about eleven across disciplines on roughly seven concurrent projects.",
    evidenceSource: "Positioning and UX brief supplied by Jamel, 14 October 2026.",
    verifier: "Jamel Williams",
    status: "verified",
  },
  {
    id: "profile-lead-03",
    projectId: "profile",
    placement: "profile-leadership",
    wording: "Responsible for business development and staffing on the studio's Los Angeles projects. This describes scope, never performance.",
    evidenceSource: "Positioning and UX brief supplied by Jamel, 14 October 2026.",
    verifier: "Jamel Williams",
    status: "verified",
  },
];
